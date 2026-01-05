#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <math.h>
#include <sys/stat.h>
#include <locale.h>
#include <signal.h>
#include <unistd.h>
#include <libgen.h>  // 用于获取目录名

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define getcwd _getcwd
#else
#include <sys/time.h>
#include <unistd.h>
#endif

// 常量定义
#define DEFAULT_SWAP_UP_DOWN 1
#define MAX_DATA_POINTS 240
#define MIN_OTHER_PERCENTAGE 5
#define MAX_OTHER_PERCENTAGE 15
#define MAX_IP_LENGTH 16
#define MAX_PROTOCOLS 6
#define MAX_LINE_LENGTH 1024
#define HASH_TABLE_SIZE 1000
#define CONFIG_FILENAME "preprocessor.conf"

// 数据字段索引
typedef enum {
    FIELD_ip = 0,
    FIELD_ts = 1,
    FIELD_in_total = 2,
    FIELD_in_icmp = 3,
    FIELD_in_tcp = 4,
    FIELD_in_http = 5,
    FIELD_in_ftp = 6,
    FIELD_in_udp = 7,
    FIELD_in_smtp = 8,
    FIELD_out_total = 9,
    FIELD_out_icmp = 10,
    FIELD_out_tcp = 11,
    FIELD_out_http = 12,
    FIELD_out_ftp = 13,
    FIELD_out_udp = 14,
    FIELD_out_smtp = 15
} FieldIndex;

// 协议定义
typedef struct {
    char key[10];
    char label[10];
    int inIdx;
    int outIdx;
} Protocol;

Protocol PROTOS[] = {
    {"icmp", "ICMP", FIELD_in_icmp, FIELD_out_icmp},
    {"tcp", "TCP", FIELD_in_tcp, FIELD_out_tcp},
    {"http", "HTTP", FIELD_in_http, FIELD_out_http},
    {"ftp", "FTP", FIELD_in_ftp, FIELD_out_ftp},
    {"udp", "UDP", FIELD_in_udp, FIELD_out_udp},
    {"smtp", "SMTP", FIELD_in_smtp, FIELD_out_smtp}
};

// 时间范围定义
typedef enum {
    RANGE_1H,
    RANGE_1D,
    RANGE_1W,
    RANGE_1M,
    RANGE_1Y,
    NUM_RANGES
} TimeRange;

const char* RANGE_NAMES[] = {"1h", "1d", "1w", "1m", "1y"};

// 配置结构
typedef struct {
    int swap_up_down;
    long interval_1h;
    long interval_1d;
    long interval_1w;
    long interval_1m;
    long interval_1y;
    int watch_mode;
    int watch_interval;
    char input_file[512];
    char output_file[512];
} Config;

// 全局配置
Config config = {
    .swap_up_down = DEFAULT_SWAP_UP_DOWN,
    .interval_1h = 0,  // 默认1小时使用原始数据点
    .interval_1d = 1400,
    .interval_1w = 8000,
    .interval_1m = 25000,
    .interval_1y = 250000,
    .watch_mode = 0,
    .watch_interval = 5,
    .input_file = "/log.1.0.cdf",
    .output_file = "preprocessed_data.json"
};

// 全局变量用于信号处理
volatile sig_atomic_t keep_running = 1;

// 信号处理函数
void handle_signal(int sig) {
    keep_running = 0;
    printf("\nReceived signal %d, shutting down...\n", sig);
}

// 获取文件修改时间
time_t get_file_mtime(const char* filename) {
    struct stat file_stat;
    if (stat(filename, &file_stat) == 0) {
        return file_stat.st_mtime;
    }
    return 0;
}

// 获取可执行文件所在目录
char* get_executable_dir() {
    static char exec_dir[1024] = {0};
    
#ifdef _WIN32
    GetModuleFileNameA(NULL, exec_dir, sizeof(exec_dir));
    char* last_slash = strrchr(exec_dir, '\\');
#else
    ssize_t len = readlink("/proc/self/exe", exec_dir, sizeof(exec_dir) - 1);
    if (len != -1) {
        exec_dir[len] = '\0';
    }
    char* last_slash = strrchr(exec_dir, '/');
#endif
    
    if (last_slash) {
        *last_slash = '\0';  // 截断文件名，只保留目录
    }
    
    return exec_dir;
}

// 构建完整路径（相对于可执行文件目录）
void build_full_path(const char* filename, char* full_path, size_t full_path_size) {
    if (filename[0] == '/' || filename[0] == '\\' || 
        (filename[1] == ':' && (filename[2] == '\\' || filename[2] == '/'))) {
        // 已经是绝对路径
        strncpy(full_path, filename, full_path_size - 1);
    } else {
        // 相对路径，基于可执行文件目录
        const char* exec_dir = get_executable_dir();
        snprintf(full_path, full_path_size, "%s/%s", exec_dir, filename);
    }
    full_path[full_path_size - 1] = '\0';
}

// 获取时间范围对应的秒数
long secondsForRange(TimeRange range) {
    switch (range) {
        case RANGE_1H: return 3600;
        case RANGE_1D: return 86400;
        case RANGE_1W: return 86400 * 7;
        case RANGE_1M: return 86400 * 30;
        case RANGE_1Y: return 86400 * 365;
        default: return 3600;
    }
}

// 获取时间范围对应的数据间隔
long chooseIntervalForRange(TimeRange range) {
    switch (range) {
        case RANGE_1H: return config.interval_1h;
        case RANGE_1D: return config.interval_1d;
        case RANGE_1W: return config.interval_1w;
        case RANGE_1M: return config.interval_1m;
        case RANGE_1Y: return config.interval_1y;
        default: return 300;
    }
}

// 检查是否应该使用原始数据点
int shouldUseRawDataPoints(TimeRange range) {
    long interval = chooseIntervalForRange(range);
    return (interval <= 0);  // 间隔为0或负数时使用原始数据点
}

// 协议数据结构
typedef struct {
    double upload;
    double download;
} ProtocolData;

// IP数据结构
typedef struct {
    double upload;
    double download;
    ProtocolData protocols[MAX_PROTOCOLS];
} IPData;

// 哈希表节点
typedef struct HashNode {
    char ip[MAX_IP_LENGTH];
    IPData data;
    struct HashNode* next;
} HashNode;

// 桶数据结构
typedef struct {
    time_t ts;
    HashNode** ipData;
} Bucket;

// 预处理桶数据
typedef struct {
    Bucket** buckets[NUM_RANGES];
    int bucketCounts[NUM_RANGES];
} PreprocessedData;

// 原始记录
typedef struct {
    char ip[MAX_IP_LENGTH];
    time_t ts;
    double values[16];
} RawRecord;

// 哈希函数
unsigned int hash(const char* ip) {
    unsigned int hash = 0;
    for (int i = 0; ip[i] != '\0'; i++) {
        hash = (hash * 31) + ip[i];
    }
    return hash % HASH_TABLE_SIZE;
}

// 在哈希表中查找或创建IP数据
IPData* getOrCreateIPData(HashNode** table, const char* ip) {
    unsigned int index = hash(ip);
    HashNode* node = table[index];
    
    while (node != NULL) {
        if (strcmp(node->ip, ip) == 0) {
            return &node->data;
        }
        node = node->next;
    }
    
    HashNode* newNode = (HashNode*)malloc(sizeof(HashNode));
    strcpy(newNode->ip, ip);
    newNode->data.upload = 0;
    newNode->data.download = 0;
    for (int i = 0; i < MAX_PROTOCOLS; i++) {
        newNode->data.protocols[i].upload = 0;
        newNode->data.protocols[i].download = 0;
    }
    newNode->next = table[index];
    table[index] = newNode;
    
    return &newNode->data;
}

// 释放哈希表
void freeHashTable(HashNode** table, int size) {
    for (int i = 0; i < size; i++) {
        HashNode* node = table[i];
        while (node != NULL) {
            HashNode* temp = node;
            node = node->next;
            free(temp);
        }
    }
    free(table);
}

// 读取配置文件
int loadConfig(const char* filename) {
    char full_path[1024];
    build_full_path(filename, full_path, sizeof(full_path));
    
    FILE* file = fopen(full_path, "r");
    if (!file) {
        printf("Config file not found: %s, using default settings\n", full_path);
        return 0;
    }
    
    char line[256];
    int loaded = 0;
    
    while (fgets(line, sizeof(line), file)) {
        if (line[0] == '#' || line[0] == '\n') continue;
        
        char key[64], value[512];
        if (sscanf(line, "%63[^=]=%511[^\n]", key, value) == 2) {
            if (strcmp(key, "swap_up_down") == 0) {
                config.swap_up_down = atoi(value);
                loaded++;
            } else if (strcmp(key, "interval_1h") == 0) {
                config.interval_1h = atol(value);
                loaded++;
            } else if (strcmp(key, "interval_1d") == 0) {
                config.interval_1d = atol(value);
                loaded++;
            } else if (strcmp(key, "interval_1w") == 0) {
                config.interval_1w = atol(value);
                loaded++;
            } else if (strcmp(key, "interval_1m") == 0) {
                config.interval_1m = atol(value);
                loaded++;
            } else if (strcmp(key, "interval_1y") == 0) {
                config.interval_1y = atol(value);
                loaded++;
            } else if (strcmp(key, "watch_interval") == 0) {
                config.watch_interval = atoi(value);
                loaded++;
            } else if (strcmp(key, "input_file") == 0) {
                strncpy(config.input_file, value, sizeof(config.input_file) - 1);
                config.input_file[sizeof(config.input_file) - 1] = '\0';
                loaded++;
            } else if (strcmp(key, "output_file") == 0) {
                strncpy(config.output_file, value, sizeof(config.output_file) - 1);
                config.output_file[sizeof(config.output_file) - 1] = '\0';
                loaded++;
            }
        }
    }
    
    fclose(file);
    printf("Loaded %d configuration settings from %s\n", loaded, full_path);
    return loaded;
}

// 创建默认配置文件
void createDefaultConfig(const char* filename) {
    char full_path[1024];
    build_full_path(filename, full_path, sizeof(full_path));
    
    FILE* file = fopen(full_path, "w");
    if (!file) {
        printf("Warning: Cannot create config file %s\n", full_path);
        return;
    }
    
    fprintf(file, "# Preprocessor Configuration File\n");
    fprintf(file, "# This file can be used to customize the preprocessor behavior\n\n");
    
    fprintf(file, "# Swap upload/download semantics (0 = false, 1 = true)\n");
    fprintf(file, "swap_up_down=%d\n\n", DEFAULT_SWAP_UP_DOWN);
    
    fprintf(file, "# Time interval for each range in seconds\n");
    fprintf(file, "# Set to 0 to use raw data points (no bucketing)\n");
    fprintf(file, "# 1h: %ld seconds (0 = use raw data points)\n", config.interval_1h);
    fprintf(file, "interval_1h=%ld\n\n", config.interval_1h);
    
    fprintf(file, "# 1d: %ld seconds (40 data points)\n", config.interval_1d);
    fprintf(file, "interval_1d=%ld\n\n", config.interval_1d);
    
    fprintf(file, "# 1w: %ld seconds (40 data points)\n", config.interval_1w);
    fprintf(file, "interval_1w=%ld\n\n", config.interval_1w);
    
    fprintf(file, "# 1m: %ld seconds (50 data points)\n", config.interval_1m);
    fprintf(file, "interval_1m=%ld\n\n", config.interval_1m);
    
    fprintf(file, "# 1y: %ld seconds (70 data points)\n", config.interval_1y);
    fprintf(file, "interval_1y=%ld\n\n", config.interval_1y);
    
    fprintf(file, "# Watch mode interval in seconds (for -w option)\n");
    fprintf(file, "watch_interval=%d\n\n", config.watch_interval);
    
    fprintf(file, "# Input file path (relative to executable directory)\n");
    fprintf(file, "input_file=%s\n\n", config.input_file);
    
    fprintf(file, "# Output file path (relative to executable directory)\n");
    fprintf(file, "output_file=%s\n", config.output_file);
    
    fclose(file);
    printf("Created default configuration file: %s\n", full_path);
}

// 解析CSV行
int parseCSVLine(const char* line, RawRecord* record) {
    char buffer[MAX_LINE_LENGTH];
    strcpy(buffer, line);
    
    char* newline = strchr(buffer, '\n');
    if (newline) *newline = '\0';
    newline = strchr(buffer, '\r');
    if (newline) *newline = '\0';
    
    char* token = strtok(buffer, ",");
    int fieldIndex = 0;
    
    while (token != NULL && fieldIndex < 16) {
        if (fieldIndex == 0) {
            strncpy(record->ip, token, MAX_IP_LENGTH - 1);
            record->ip[MAX_IP_LENGTH - 1] = '\0';
        } else if (fieldIndex == 1) {
            record->ts = (time_t)atol(token);
        } else {
            record->values[fieldIndex] = atof(token);
        }
        
        token = strtok(NULL, ",");
        fieldIndex++;
    }
    
    while (fieldIndex < 16) {
        record->values[fieldIndex] = 0;
        fieldIndex++;
    }
    
    return (fieldIndex >= 2);
}

// 读取CSV文件
RawRecord* readCSVFile(const char* filename, int* recordCount) {
    char full_path[1024];
    build_full_path(filename, full_path, sizeof(full_path));
    
    FILE* file = fopen(full_path, "r");
    if (!file) {
        printf("Cannot open file: %s\n", full_path);
        return NULL;
    }
    
    int capacity = 1000;
    int count = 0;
    RawRecord* records = (RawRecord*)malloc(capacity * sizeof(RawRecord));
    char line[MAX_LINE_LENGTH];
    
    while (fgets(line, sizeof(line), file)) {
        if (strlen(line) <= 1 || line[0] == '#') continue;
        
        if (count >= capacity) {
            capacity *= 2;
            RawRecord* newRecords = (RawRecord*)realloc(records, capacity * sizeof(RawRecord));
            if (!newRecords) {
                printf("Memory allocation failed\n");
                free(records);
                fclose(file);
                return NULL;
            }
            records = newRecords;
        }
        
        if (parseCSVLine(line, &records[count])) {
            count++;
        }
    }
    
    fclose(file);
    *recordCount = count;
    
    if (count == 0) {
        free(records);
        return NULL;
    }
    
    return records;
}

// 使用原始数据点创建桶
int createRawDataBuckets(TimeRange range, RawRecord* records, int recordCount, Bucket*** buckets) {
    time_t currentTime = time(NULL);
    long rangeSec = secondsForRange(range);
    time_t from = currentTime - rangeSec;
    
    // 收集在时间范围内的原始记录
    int validRecordsCount = 0;
    for (int i = 0; i < recordCount; i++) {
        if (records[i].ts >= from && records[i].ts <= currentTime) {
            validRecordsCount++;
        }
    }
    
    if (validRecordsCount == 0) {
        *buckets = NULL;
        return 0;
    }
    
    // 按时间戳分组原始记录
    typedef struct {
        time_t timestamp;
        RawRecord** records;
        int count;
        int capacity;
    } TimeGroup;
    
    TimeGroup* timeGroups = NULL;
    int groupCount = 0;
    int groupCapacity = 0;
    
    // 创建时间戳分组
    for (int i = 0; i < recordCount; i++) {
        if (records[i].ts < from || records[i].ts > currentTime) {
            continue;
        }
        
        time_t ts = records[i].ts;
        
        // 查找是否已存在该时间戳的分组
        int found = -1;
        for (int j = 0; j < groupCount; j++) {
            if (timeGroups[j].timestamp == ts) {
                found = j;
                break;
            }
        }
        
        if (found == -1) {
            // 创建新分组
            if (groupCount >= groupCapacity) {
                groupCapacity = groupCapacity == 0 ? 16 : groupCapacity * 2;
                TimeGroup* newGroups = (TimeGroup*)realloc(timeGroups, groupCapacity * sizeof(TimeGroup));
                if (!newGroups) {
                    printf("Memory allocation failed\n");
                    if (timeGroups) {
                        for (int k = 0; k < groupCount; k++) {
                            free(timeGroups[k].records);
                        }
                        free(timeGroups);
                    }
                    return -1;
                }
                timeGroups = newGroups;
            }
            
            timeGroups[groupCount].timestamp = ts;
            timeGroups[groupCount].capacity = 8;
            timeGroups[groupCount].count = 0;
            timeGroups[groupCount].records = (RawRecord**)malloc(8 * sizeof(RawRecord*));
            if (!timeGroups[groupCount].records) {
                printf("Memory allocation failed\n");
                for (int k = 0; k < groupCount; k++) {
                    free(timeGroups[k].records);
                }
                free(timeGroups);
                return -1;
            }
            
            found = groupCount;
            groupCount++;
        }
        
        // 添加记录到分组
        TimeGroup* group = &timeGroups[found];
        if (group->count >= group->capacity) {
            group->capacity *= 2;
            RawRecord** newRecords = (RawRecord**)realloc(group->records, group->capacity * sizeof(RawRecord*));
            if (!newRecords) {
                printf("Memory allocation failed\n");
                for (int k = 0; k < groupCount; k++) {
                    free(timeGroups[k].records);
                }
                free(timeGroups);
                return -1;
            }
            group->records = newRecords;
        }
        
        group->records[group->count] = &records[i];
        group->count++;
    }
    
    // 为时间范围创建桶
    *buckets = (Bucket**)malloc(groupCount * sizeof(Bucket*));
    if (!*buckets) {
        printf("Memory allocation failed\n");
        for (int i = 0; i < groupCount; i++) {
            free(timeGroups[i].records);
        }
        free(timeGroups);
        return -1;
    }
    
    // 处理每个时间分组
    for (int i = 0; i < groupCount; i++) {
        TimeGroup* group = &timeGroups[i];
        
        (*buckets)[i] = (Bucket*)malloc(sizeof(Bucket));
        (*buckets)[i]->ts = group->timestamp;
        (*buckets)[i]->ipData = (HashNode**)calloc(HASH_TABLE_SIZE, sizeof(HashNode*));
        if (!(*buckets)[i]->ipData) {
            printf("Memory allocation failed\n");
            for (int j = 0; j <= i; j++) {
                if ((*buckets)[j]) {
                    if ((*buckets)[j]->ipData) free((*buckets)[j]->ipData);
                    free((*buckets)[j]);
                }
            }
            free(*buckets);
            *buckets = NULL;
            for (int k = 0; k < groupCount; k++) {
                free(timeGroups[k].records);
            }
            free(timeGroups);
            return -1;
        }
        
        // 处理该时间戳的所有记录
        for (int j = 0; j < group->count; j++) {
            RawRecord* record = group->records[j];
            Bucket* bucket = (*buckets)[i];
            IPData* ipData = getOrCreateIPData(bucket->ipData, record->ip);
            
            double uploadVal, downloadVal;
            if (config.swap_up_down) {
                uploadVal = record->values[FIELD_in_total];
                downloadVal = record->values[FIELD_out_total];
            } else {
                uploadVal = record->values[FIELD_out_total];
                downloadVal = record->values[FIELD_in_total];
            }
            
            ipData->upload += uploadVal;
            ipData->download += downloadVal;
            
            for (int p = 0; p < MAX_PROTOCOLS; p++) {
                Protocol* proto = &PROTOS[p];
                double protoUpload, protoDownload;
                
                if (config.swap_up_down) {
                    protoUpload = record->values[proto->inIdx];
                    protoDownload = record->values[proto->outIdx];
                } else {
                    protoUpload = record->values[proto->outIdx];
                    protoDownload = record->values[proto->inIdx];
                }
                
                ipData->protocols[p].upload += protoUpload;
                ipData->protocols[p].download += protoDownload;
            }
        }
    }
    
    // 释放时间分组内存
    for (int i = 0; i < groupCount; i++) {
        free(timeGroups[i].records);
    }
    free(timeGroups);
    
    // 按时间戳排序
    for (int i = 0; i < groupCount - 1; i++) {
        for (int j = i + 1; j < groupCount; j++) {
            if ((*buckets)[i]->ts > (*buckets)[j]->ts) {
                Bucket* temp = (*buckets)[i];
                (*buckets)[i] = (*buckets)[j];
                (*buckets)[j] = temp;
            }
        }
    }
    
    return groupCount;
}

// 使用分桶方式创建桶
int createTimeBuckets(TimeRange range, RawRecord* records, int recordCount, Bucket*** buckets) {
    time_t currentTime = time(NULL);
    long rangeSec = secondsForRange(range);
    long bucketSec = chooseIntervalForRange(range);
    time_t from = currentTime - rangeSec;
    
    int bucketCount = (int)ceil((double)rangeSec / bucketSec);
    if (bucketCount <= 0) bucketCount = 1;
    
    *buckets = (Bucket**)malloc(bucketCount * sizeof(Bucket*));
    if (!*buckets) {
        printf("Memory allocation failed\n");
        return -1;
    }
    
    for (int i = 0; i < bucketCount; i++) {
        (*buckets)[i] = (Bucket*)malloc(sizeof(Bucket));
        (*buckets)[i]->ts = from + i * bucketSec;
        (*buckets)[i]->ipData = (HashNode**)calloc(HASH_TABLE_SIZE, sizeof(HashNode*));
        if (!(*buckets)[i]->ipData) {
            printf("Memory allocation failed\n");
            for (int j = 0; j <= i; j++) {
                if ((*buckets)[j]) {
                    if ((*buckets)[j]->ipData) free((*buckets)[j]->ipData);
                    free((*buckets)[j]);
                }
            }
            free(*buckets);
            *buckets = NULL;
            return -1;
        }
    }
    
    // 填充数据到桶中
    for (int i = 0; i < recordCount; i++) {
        RawRecord* record = &records[i];
        
        if (record->ts < from || record->ts > currentTime) {
            continue;
        }
        
        int bucketIndex = (int)((record->ts - from) / bucketSec);
        if (bucketIndex < 0 || bucketIndex >= bucketCount) {
            continue;
        }
        
        Bucket* bucket = (*buckets)[bucketIndex];
        IPData* ipData = getOrCreateIPData(bucket->ipData, record->ip);
        
        double uploadVal, downloadVal;
        if (config.swap_up_down) {
            uploadVal = record->values[FIELD_in_total];
            downloadVal = record->values[FIELD_out_total];
        } else {
            uploadVal = record->values[FIELD_out_total];
            downloadVal = record->values[FIELD_in_total];
        }
        
        ipData->upload += uploadVal;
        ipData->download += downloadVal;
        
        for (int p = 0; p < MAX_PROTOCOLS; p++) {
            Protocol* proto = &PROTOS[p];
            double protoUpload, protoDownload;
            
            if (config.swap_up_down) {
                protoUpload = record->values[proto->inIdx];
                protoDownload = record->values[proto->outIdx];
            } else {
                protoUpload = record->values[proto->outIdx];
                protoDownload = record->values[proto->inIdx];
            }
            
            ipData->protocols[p].upload += protoUpload;
            ipData->protocols[p].download += protoDownload;
        }
    }
    
    return bucketCount;
}

// 预处理所有数据
PreprocessedData* preprocessAllData(RawRecord* records, int recordCount) {
    if (recordCount == 0) {
        return NULL;
    }
    
    PreprocessedData* data = (PreprocessedData*)malloc(sizeof(PreprocessedData));
    if (!data) {
        printf("Memory allocation failed\n");
        return NULL;
    }
    
    for (int i = 0; i < NUM_RANGES; i++) {
        data->buckets[i] = NULL;
        data->bucketCounts[i] = 0;
    }
    
    // 为每个时间范围预处理数据
    for (int r = 0; r < NUM_RANGES; r++) {
        TimeRange range = (TimeRange)r;
        int bucketCount;
        
        if (shouldUseRawDataPoints(range)) {
            // 使用原始数据点
            printf("Preprocessing %s: using raw data points\n", RANGE_NAMES[r]);
            bucketCount = createRawDataBuckets(range, records, recordCount, &data->buckets[r]);
        } else {
            // 使用分桶方式
            printf("Preprocessing %s: using time buckets\n", RANGE_NAMES[r]);
            bucketCount = createTimeBuckets(range, records, recordCount, &data->buckets[r]);
        }
        
        if (bucketCount < 0) {
            printf("Error: Failed to create buckets for range %s\n", RANGE_NAMES[r]);
            // 清理已分配的内存
            for (int i = 0; i < r; i++) {
                if (data->buckets[i]) {
                    for (int j = 0; j < data->bucketCounts[i]; j++) {
                        freeHashTable(data->buckets[i][j]->ipData, HASH_TABLE_SIZE);
                        free(data->buckets[i][j]);
                    }
                    free(data->buckets[i]);
                }
            }
            free(data);
            return NULL;
        }
        
        data->bucketCounts[r] = bucketCount;
        printf("Preprocessing %s: %d %s\n", RANGE_NAMES[r], bucketCount, 
               shouldUseRawDataPoints(range) ? "raw data points" : "buckets");
    }
    
    return data;
}

// 格式化字节数为可读字符串
void formatBytes(double bytes, char* buffer, int bufferSize) {
    const char* units[] = {"B", "KB", "MB", "GB", "TB"};
    int unitIndex = 0;
    double value = fabs(bytes);
    
    while (value >= 1024 && unitIndex < 4) {
        value /= 1024;
        unitIndex++;
    }
    
    if (bytes < 0) {
        snprintf(buffer, bufferSize, "-%.2f%s", value, units[unitIndex]);
    } else {
        snprintf(buffer, bufferSize, "%.2f%s", value, units[unitIndex]);
    }
}

// 导出预处理数据为JSON（紧凑格式）
void exportPreprocessedData(PreprocessedData* data, const char* filename) {
    char full_path[1024];
    build_full_path(filename, full_path, sizeof(full_path));
    
    FILE* file = fopen(full_path, "w");
    if (!file) {
        printf("Cannot create file: %s\n", full_path);
        return;
    }
    
    fprintf(file, "{\n");
    fprintf(file, "  \"ts\": %ld,\n", (long)time(NULL));
    
    int totalBuckets = 0;
    for (int r = 0; r < NUM_RANGES; r++) {
        totalBuckets += data->bucketCounts[r];
    }
    
    fprintf(file, "  \"total\": %d,\n", totalBuckets);
    fprintf(file, "  \"ranges\": {\n");
    
    for (int r = 0; r < NUM_RANGES; r++) {
        fprintf(file, "    \"%s\": {\n", RANGE_NAMES[r]);
        fprintf(file, "      \"cnt\": %d,\n", data->bucketCounts[r]);
        fprintf(file, "      \"buckets\": [\n");
        
        for (int i = 0; i < data->bucketCounts[r]; i++) {
            Bucket* bucket = data->buckets[r][i];
            
            fprintf(file, "        {\n");
            fprintf(file, "          \"ts\": %ld,\n", (long)bucket->ts);
            
            char timeBuffer[64];
            struct tm* timeinfo = localtime(&bucket->ts);
            strftime(timeBuffer, sizeof(timeBuffer), "%Y-%m-%d %H:%M:%S", timeinfo);
            fprintf(file, "          \"t\": \"%s\",\n", timeBuffer);
            
            fprintf(file, "          \"d\": {\n");
            
            int ipCount = 0;
            for (int h = 0; h < HASH_TABLE_SIZE; h++) {
                HashNode* node = bucket->ipData[h];
                while (node != NULL) {
                    if (ipCount > 0) {
                        fprintf(file, ",\n");
                    }
                    
                    fprintf(file, "            \"%s\": [%.2f,%.2f", node->ip, 
                            node->data.upload, node->data.download);
                    
                    for (int p = 0; p < MAX_PROTOCOLS; p++) {
                        fprintf(file, ",%.2f,%.2f", 
                                node->data.protocols[p].upload,
                                node->data.protocols[p].download);
                    }
                    
                    fprintf(file, "]");
                    
                    ipCount++;
                    node = node->next;
                }
            }
            
            if (ipCount == 0) {
                fprintf(file, "\n          }\n");
            } else {
                fprintf(file, "\n          }\n");
            }
            
            fprintf(file, "        }%s\n", (i < data->bucketCounts[r] - 1) ? "," : "");
        }
        
        fprintf(file, "      ]\n");
        fprintf(file, "    }%s\n", (r < NUM_RANGES - 1) ? "," : "");
    }
    
    fprintf(file, "  }\n");
    fprintf(file, "}\n");
    
    fclose(file);
    printf("Preprocessed data exported to: %s (total %d buckets)\n", full_path, totalBuckets);
}

// 释放预处理数据
void freePreprocessedData(PreprocessedData* data) {
    if (!data) return;
    
    for (int r = 0; r < NUM_RANGES; r++) {
        if (data->buckets[r]) {
            for (int i = 0; i < data->bucketCounts[r]; i++) {
                if (data->buckets[r][i]) {
                    if (data->buckets[r][i]->ipData) {
                        freeHashTable(data->buckets[r][i]->ipData, HASH_TABLE_SIZE);
                    }
                    free(data->buckets[r][i]);
                }
            }
            free(data->buckets[r]);
        }
    }
    free(data);
}

// 显示统计信息
void showPreprocessedStats(PreprocessedData* data) {
    printf("=== Preprocessed Data Statistics ===\n");
    
    int totalRecords = 0;
    
    for (int r = 0; r < NUM_RANGES; r++) {
        int rangeRecords = 0;
        double rangeUpload = 0, rangeDownload = 0;
        
        for (int i = 0; i < data->bucketCounts[r]; i++) {
            Bucket* bucket = data->buckets[r][i];
            
            for (int h = 0; h < HASH_TABLE_SIZE; h++) {
                HashNode* node = bucket->ipData[h];
                while (node != NULL) {
                    rangeRecords++;
                    rangeUpload += node->data.upload;
                    rangeDownload += node->data.download;
                    node = node->next;
                }
            }
        }
        
        totalRecords += rangeRecords;
        
        char uploadStr[20], downloadStr[20], totalStr[20];
        formatBytes(rangeUpload, uploadStr, sizeof(uploadStr));
        formatBytes(rangeDownload, downloadStr, sizeof(downloadStr));
        formatBytes(rangeUpload + rangeDownload, totalStr, sizeof(totalStr));
        
        printf("%s:\n", RANGE_NAMES[r]);
        printf("  Bucket count: %d\n", data->bucketCounts[r]);
        printf("  Data records: %d\n", rangeRecords);
        printf("  Total upload: %s\n", uploadStr);
        printf("  Total download: %s\n", downloadStr);
        printf("  Total traffic: %s\n", totalStr);
    }
    
    printf("=== Summary ===\n");
    int totalBuckets = 0;
    for (int r = 0; r < NUM_RANGES; r++) {
        totalBuckets += data->bucketCounts[r];
    }
    printf("Total buckets: %d\n", totalBuckets);
    printf("Total data records: %d\n", totalRecords);
}

// 显示配置信息
void showConfig() {
    printf("=== Current Configuration ===\n");
    printf("swap_up_down: %d\n", config.swap_up_down);
    printf("interval_1h: %ld seconds (%s)\n", config.interval_1h, 
           shouldUseRawDataPoints(RANGE_1H) ? "raw data points" : "time buckets");
    printf("interval_1d: %ld seconds (%s)\n", config.interval_1d, 
           shouldUseRawDataPoints(RANGE_1D) ? "raw data points" : "time buckets");
    printf("interval_1w: %ld seconds (%s)\n", config.interval_1w, 
           shouldUseRawDataPoints(RANGE_1W) ? "raw data points" : "time buckets");
    printf("interval_1m: %ld seconds (%s)\n", config.interval_1m, 
           shouldUseRawDataPoints(RANGE_1M) ? "raw data points" : "time buckets");
    printf("interval_1y: %ld seconds (%s)\n", config.interval_1y, 
           shouldUseRawDataPoints(RANGE_1Y) ? "raw data points" : "time buckets");
    printf("watch_interval: %d seconds\n", config.watch_interval);
    printf("input_file: %s\n", config.input_file);
    printf("output_file: %s\n", config.output_file);
    printf("=============================\n\n");
}

// 处理单个文件
int processFile(const char* inputFile, const char* outputFile) {
    char input_full_path[1024];
    build_full_path(inputFile, input_full_path, sizeof(input_full_path));
    
    struct stat buffer;
    if (stat(input_full_path, &buffer) != 0) {
        printf("Error: Input file does not exist: %s\n", input_full_path);
        return 0;
    }
    
    int recordCount;
    RawRecord* records = readCSVFile(inputFile, &recordCount);
    
    if (!records || recordCount == 0) {
        printf("Error: Unable to read data or data is empty\n");
        return 0;
    }
    
    printf("Successfully read %d records from %s\n", recordCount, input_full_path);
    
    PreprocessedData* preprocessedData = preprocessAllData(records, recordCount);
    
    if (!preprocessedData) {
        printf("Error: Preprocessing failed\n");
        free(records);
        return 0;
    }
    
    showPreprocessedStats(preprocessedData);
    exportPreprocessedData(preprocessedData, outputFile);
    
    freePreprocessedData(preprocessedData);
    free(records);
    
    printf("Processing completed successfully!\n");
    
    char output_full_path[1024];
    build_full_path(outputFile, output_full_path, sizeof(output_full_path));
    printf("Output saved to: %s\n\n", output_full_path);
    
    return 1;
}

// 显示使用说明
void showUsage(const char* programName) {
    printf("Usage: %s [options] [input_file] [output_file]\n", programName);
    printf("\nOptions:\n");
    printf("  -w, --watch        Enable watch mode (monitor file for changes)\n");
    printf("  -h, --help         Show this help message\n");
    printf("\nArguments:\n");
    printf("  input_file         Input CSV file (overrides config)\n");
    printf("  output_file        Output JSON file (overrides config)\n");
    printf("\nFile Resolution:\n");
    printf("  - All file paths are relative to the executable directory\n");
    printf("  - Command line arguments override config file settings\n");
    printf("  - Config file is stored in executable directory: %s\n", CONFIG_FILENAME);
    printf("\nBucket Configuration:\n");
    printf("  - Set interval to 0 to use raw data points (no bucketing)\n");
    printf("  - Default: 1h uses raw data points, others use time buckets\n");
    printf("\nExamples:\n");
    printf("  %s                            # Use config file settings\n", programName);
    printf("  %s data.csv                   # Override input file only\n", programName);
    printf("  %s input.csv output.json      # Override both files\n", programName);
    printf("  %s -w                         # Watch mode with config settings\n", programName);
    printf("  %s -w data.csv output.json    # Watch mode with custom files\n", programName);
}

// 获取当前时间字符串
const char* get_current_time_string() {
    static char time_buffer[64];
    time_t now = time(NULL);
    struct tm* timeinfo = localtime(&now);
    strftime(time_buffer, sizeof(time_buffer), "%Y-%m-%d %H:%M:%S", timeinfo);
    return time_buffer;
}

// 主函数
int main(int argc, char* argv[]) {
    setlocale(LC_ALL, "");
    
    // 设置信号处理
    signal(SIGINT, handle_signal);
    signal(SIGTERM, handle_signal);
    
    // 显示可执行文件目录
    printf("Executable directory: %s\n", get_executable_dir());
    
    // 加载配置
    if (loadConfig(CONFIG_FILENAME) == 0) {
        createDefaultConfig(CONFIG_FILENAME);
    }
    
    // 解析命令行参数
    const char* inputFile = config.input_file;
    const char* outputFile = config.output_file;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-w") == 0 || strcmp(argv[i], "--watch") == 0) {
            config.watch_mode = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            showUsage(argv[0]);
            return 0;
        } else if (i == argc - 2) {
            inputFile = argv[i];
        } else if (i == argc - 1) {
            outputFile = argv[i];
        }
    }
    
    showConfig();
    
    if (config.watch_mode) {
        printf("Watch mode enabled\n");
        printf("Monitoring input file: %s\n", inputFile);
        printf("Output file: %s\n", outputFile);
        printf("Check interval: %d seconds\n", config.watch_interval);
        printf("Press Ctrl+C to stop\n\n");
        
        char input_full_path[1024];
        build_full_path(inputFile, input_full_path, sizeof(input_full_path));
        
        time_t last_mtime = 0;
        int process_count = 0;
        
        while (keep_running) {
            time_t current_mtime = get_file_mtime(input_full_path);
            
            if (current_mtime > last_mtime) {
                printf("[%s] File change detected, reprocessing...\n", 
                       get_current_time_string());
                
                if (processFile(inputFile, outputFile)) {
                    process_count++;
                    last_mtime = current_mtime;
                } else {
                    printf("Processing failed, will retry...\n");
                }
            }
            
            if (keep_running) {
                sleep(config.watch_interval);
            }
        }
        
        printf("\nWatch mode stopped. Processed %d times.\n", process_count);
    } else {
        // 单次处理模式
        printf("Input file: %s\n", inputFile);
        printf("Output file: %s\n\n", outputFile);
        
        if (!processFile(inputFile, outputFile)) {
            return 1;
        }
    }
    
    return 0;
}
#ifndef MMINER_H
#define MMINER_H

#include <stddef.h>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <cstdlib>
#include <sys/time.h>
#include <cmath>
#include <sys/types.h>
#include <unistd.h>

#include <gmp.h>
#include <signal.h>
#include <getopt.h>
#include "cuda_helper.h"

#include <jansson.h>
#include <curl/curl.h>

#define DEBUG 0
#define FULL 0
#define MINOR 1

#if DEBUG

#define DEFAULT_ADDRESS "0xbb5e958846f2e246faa3bccbba89f10c37ac3996"
#define DEFAULT_LASTMINED "0x0"

#define DEFAULT_CONTROLLER "http://localhost:17395"
// #define DEFAULT_LASTMINED "0x422000000003B0019000000"

#define DEFAULT_DIFFICULTY "5731203885580"
#define DEFAULT_MINOR "0x7a2aff56698420"
// 5ad28c16579ae2

#else
// #define DEFAULT_CONTROLLER "http://localhost:17394"
#define DEFAULT_CONTROLLER "http://trust-in.info:17395"
#define DEFAULT_ADDRESS "0xE8946EC499a839c72E60bA7d437E28cd73a3f487"
#define DEFAULT_LASTMINED "0x422000000003B0019000000"
#define DEFAULT_DIFFICULTY "5731203885580"
#define DEFAULT_MINOR "0"

#endif

#define R 1088
#define B 1600
#define W 64
#define C 512
#define DATA_BLOCK_SIZE (R / W)
#define BLOCK_SIZE (B / W)
#define HASH_SIZE (C / 2 / 8)
#define Nr 24
#define SUFFIX 0x01

#if DEBUG
#define BLOCKNUM 2
#define BLOCKX (2)
#else
#define BLOCKNUM 20000
// #define BLOCKX (128)
// #define BLOCKNUM 16
#define BLOCKX (128)
#endif

#define STREAMNUM 5
#define POLL_TIME 30 // seconds

#define BLOCKSIZE (DATA_BLOCK_SIZE * 8)
#define SUMDATASIZE (BLOCKSIZE * BLOCKNUM * BLOCKX)

#define VERSION "1.5.1"

typedef struct OPTS
{
    char *str_address;
    char *start_address;
    char *str_lastMined;
    char *str_difficulty;
    uint64_t upper_difficulty;
    uint64_t lower_difficulty;
    char *str_startNonce;
    uint64_t startNonce;
    int device;
    bool test;
    bool use_controller;
    bool values_changed;
    char *str_minor;
    uint64_t upper_minor;
    uint64_t lower_minor;
    const char *controller;
} OPTS;

#endif

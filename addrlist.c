/**
 * @file addrlist.c
 * @author 5IGI0
 * @brief A small library to manage IP address whitelist/blacklist
 * @version 1.0
 * @date 2021-06-05
 * 
 * @copyright Copyright (c) 2021
 * 
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <arpa/inet.h>

#include "addrlist.h"

static uint8_t getBits(const uint8_t a) {
    switch (a)
    {
        case 1: return 0x80;
        case 2: return 0xC0;
        case 3: return 0xE0;
        case 4: return 0xF0;
        case 5: return 0xF8;
        case 6: return 0xFC;
        case 7: return 0xFE;
        case 8: return 0xFF;
        default: return 0xFF;
    }
}

int addrlist_checkAddr(const addrlist_addr_t addr, const addrlist_list_t addrList) {
    for (size_t i = 0; i < addrList.size; i++) {
        if (addrList.entries[i].addr.type != addr.type)
            continue;
        
        uint8_t CIDR = addrList.entries[i].CIDR;
        uint8_t j = 0;
        uint8_t is_matching = 1;

        while (CIDR) {
            uint8_t bits = getBits(CIDR);
            CIDR = (CIDR>=8) ? (CIDR-8) : 0;

            if ((addr.addr[j] & bits) != (addrList.entries[i].addr.addr[j] & bits)) {
                is_matching = 0;
                break;
            }

            j += 1;
        }

        if (is_matching)
            return 1;
    }
    return 0;
}

int addrlist_checkAddrStr(const char *addr, const addrlist_list_t addrList) {
    addrlist_addr_t addrEntry;
    int err = 0;

    if ((err=addrlist_strToAddr(addr, &addrEntry))!=0)
        return err;

    err = addrlist_checkAddr(addrEntry, addrList);

    free(addrEntry.addr);
    
    return err;
}

int addrlist_checkSockAddr(const struct sockaddr *addr, const addrlist_list_t addrList) {
    addrlist_addr_t addrEntry;

    if (addr->sa_family == AF_INET) { // if IPv4
        addrEntry.addr = (uint8_t*)&((struct sockaddr_in *)addr)->sin_addr.s_addr;
        addrEntry.type = IPV4;
        return addrlist_checkAddr(addrEntry, addrList);
    }
    
    return -__LINE__;
}

int addrlist_strToAddr(const char *addr, addrlist_addr_t *addrEntry) {
    uint8_t tmp[4];

    if (inet_pton(AF_INET, addr, &tmp) != 1)
        return -__LINE__;

    addrEntry->addr = calloc(4,1);
    addrEntry->type = IPV4;

    if (!addrEntry->addr)
        return -__LINE__;

    memcpy(addrEntry->addr, tmp, 4);

    return 0;
}

int addrlist_addAddr(const addrlist_entry_t addr, addrlist_list_t *list) {

    addrlist_entry_t *tmp = NULL;

    if (!list->size)
        tmp = calloc(1, sizeof(addrlist_entry_t));
    else
        tmp = realloc(list->entries, sizeof(addrlist_entry_t)*(list->size+1));
    
    if (!tmp)
        return -__LINE__;
    
    list->entries = tmp;
    list->size += 1;
    list->entries[list->size-1] = addr;

    return 0;
}

int addrlist_addAddrStr(const char *addr, addrlist_list_t *list) {
    addrlist_entry_t entry;
    unsigned int CIDR = 0;
    int err;
    char addrstr[INET_ADDRSTRLEN] = "";
    size_t to_check = (strlen(addr)<INET_ADDRSTRLEN) ? strlen(addr) : INET_ADDRSTRLEN;

    if (to_check==0)
        return -__LINE__;    

    // separating address from CIDR / semi-validating address
    for (size_t i = 0; i < to_check; i++) {

        if (i == INET_ADDRSTRLEN-1) {
            if (addr[i] != '/')
                return -__LINE__;
            else {
                CIDR = 1;
            }
        }
            

        if ((addr[i] >= '0' && addr[i] <= '9') || addr[i] == '.') {
            addrstr[i] = addr[i];
            continue;
        } else if (addr[i] == '/') {
            CIDR = 1;
            break;
        } else {
            return -__LINE__;
        }
    }
    
    if (CIDR == 1) {
        sscanf(addr+strlen(addrstr)+1, "%u", &CIDR);
    } else {
        CIDR = IPV4_MAX_CIDR;
    }

    if (CIDR > IPV4_MAX_CIDR)
        return -__LINE__;

    entry.CIDR = CIDR;
    
    if ((err=addrlist_strToAddr(addrstr, &entry.addr))!=0)
        return err;
    
    if((err=addrlist_addAddr(entry, list)) != 0) {
        free(entry.addr.addr);
        return err;
    }
    
    return 0;

}

void addrlist_freeList(addrlist_list_t *list) {

    for (size_t i = 0; i < list->size; i++) {
        free(list->entries[i].addr.addr);
    }
    
    list->size = 0;
    free(list->entries);
    list->entries = NULL;
}


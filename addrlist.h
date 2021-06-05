#ifndef __LIB_ADDRLIST_H__
#define __LIB_ADDRLIST_H__

#include <stdlib.h>
#include <stdint.h>

typedef enum {
    IPV4
} addrlist_addrtype_t;

typedef struct {
    uint8_t *addr;            //>> IP address
    addrlist_addrtype_t type; //>> Address type
} addrlist_addr_t;

typedef struct {
    addrlist_addr_t addr;
    uint8_t CIDR;             //>> CIDR
} addrlist_entry_t;

typedef struct {
    addrlist_entry_t *entries;
    size_t size;
} addrlist_list_t;

// functions

/**
 * @brief Check if ADDR match to ADDRLIST
 * 
 * @param addr Address to check
 * @param addrList Address list
 * @return Returns true (1) or false (0), or -X for errors.
 */
int addrlist_checkAddr(const addrlist_addr_t addr, const addrlist_list_t addrList);

/**
 * @brief Check if ADDR match to ADDRLIST
 * 
 * @param addr Address to check
 * @param addrList Address list
 * @return Returns true (1) or false (0), or -X for errors.
 */
int addrlist_checkAddrStr(const char *addr, const addrlist_list_t addrList);

/**
 * @brief Convert an IP address string into an address
 * 
 * @param addr IP address string
 * @param addrEntry Receptable to the conversion
 * @return Returns 0 on success, -X for errors. !! The IP address is dynamically allocated, you need to free it by yourself !!
 */
int addrlist_strToAddr(const char *addr, addrlist_addr_t *addrEntry);

/**
 * @brief Add an IP address to an address list
 * 
 * @param addr Address
 * @param list Address list
 * @return return 0 on success, -X on errors.
 */
int addrlist_addAddr(const addrlist_entry_t addr, addrlist_list_t *list);

/**
 * @brief Clean a list
 * 
 * @param list List
 */
void addrlist_freeList(addrlist_list_t *list);

/**
 * @brief Add an IP address to a list
 * 
 * @param addr Address (with CIDR or not)
 * @param list List
 * @return Returns 0 on success, -X on errors
 */
int addrlist_addAddrStr(const char *addr, addrlist_list_t *list);

/**
 * @brief Check if ADDR match to ADDRLIST
 * 
 * @param addr sockaddr
 * @param addrList List
 * @return Returns true (1) or false (0), or -X for errors.
 */
int addrlist_checkSockAddr(const struct sockaddr *addr, const addrlist_list_t addrList);

// defines
#define IPV4_MAX_CIDR 32

#endif
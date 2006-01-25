/*   $OSSEC, config.h, v0.x, xxxx/xx/xx, Daniel B. Cid$   */

/* Copyright (C) 2003,2004,2005 Daniel B. Cid <dcid@ossec.net>
 * All right reserved.
 *
 * This program is a free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

 

#ifndef _CONFIG__H

#define _CONFIG__H

#include "active-response.h"

/* Configuration structure */
typedef struct __Config
{
    int logall;
    int mailnotify;
    int ar;
    int stats;
    int integrity;
    int rootcheck;
    int memorysize; /* For stateful analysis */
    int keeplogdate;
    
    int mailbylevel;
    int logbylevel;

    char **syscheck_ignore;
    char **white_list;
    
}_Config;


_Config Config;  /* Global Config structure */



#endif

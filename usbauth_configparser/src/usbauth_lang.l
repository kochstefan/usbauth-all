/*
 * Copyright (c) 2015 SUSE LLC. All Rights Reserved.
 * Author: Stefan Koch <skoch@suse.de>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2.1 of the GNU Lesser General
 * Public License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program; if not, contact SUSE LLC.
 *
 * To contact SUSE about this file by physical or electronic mail,
 * you may find current contact information at www.suse.com
 */

%option prefix="usbauth_yy"

%{
#include "usbauth_lang.tab.h"

%}

%option noyywrap

%%
"allow" {return allow;}
"deny" {return deny;}
"condition" {return condition;}
"all" {return all;}
"case" {return case_;}
"anyChild" {return anyChild;}
[a-zA-Z0-9"."]+ {return name;}
("=="|"!="|"<="|">="|"<"|">") {return op;}
"\n" {return nl;}
<<EOF>> {static unsigned cnt = 0; return cnt++ ? 0 : nl;}
["#"][^\n]* {return comment;}
%%

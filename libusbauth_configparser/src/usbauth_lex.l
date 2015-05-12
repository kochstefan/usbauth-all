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

%option noinput
%option nounput
%option noyywrap

%{
#include "usbauth_syn.tab.h"
%}

%start COMMENT VAL

%%
<COMMENT>.* {BEGIN 0; return t_comment;}
<VAL>[^\n \t]+ {BEGIN 0; return t_val;}

[ \t] {;}
"#" {BEGIN COMMENT;}
"allow" {return t_allow;}
"deny" {return t_deny;}
"condition" {return t_condition;}
"all" {return t_all;}
"case" {return t_case;}
"anyChild" {return t_anyChild;}
[a-zA-Z0-9]+ {return t_name;}
("=="|"!="|"<="|">="|"<"|">") {BEGIN VAL; return t_op;}
"\n" {return t_nl;}
<<EOF>> {static unsigned cnt = 0; return cnt++ ? 0 : t_nl;}
%%

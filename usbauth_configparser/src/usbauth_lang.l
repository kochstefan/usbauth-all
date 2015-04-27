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

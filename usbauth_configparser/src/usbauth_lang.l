%option prefix="usbauth_yy"

%{
#include "usbauth_lang.tab.h"

%}

%option noyywrap

%%
["#"][a-zA-Z0-9]* {return comment;}
"allow" {return allow;}
"deny" {return deny;}
"condition" {printf("%s", yytext); return condition;}
"all" {return all;}
"case" {return case_;}
"anyChild" {return anyChild;}
[0-9a-fA-F]+ {return val;}
[a-zA-Z0-9]+ {return param;}
("=="|"!="|"<="|">="|"<"|">") {return op;}
"\n" {return nl;}
<<EOF>> {static unsigned cnt = 0; return cnt++ ? 0 : nl;}
%%

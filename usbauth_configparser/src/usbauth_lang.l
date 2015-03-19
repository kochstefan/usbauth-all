%option prefix="usbauth_yy"

%{
#include "usbauth_lang.tab.h"

/*"busnum" {return par_busnum;}
"devpath" {return par_devpath;}
"idVendor" {return par_idVendor;}
"idProduct" {return par_idProduct;}
"bDeviceClass" {return par_bDeviceClass;}
"bDeviceSubClass" {return par_bDeviceSubClass;}
"bConfigurationValue" {return par_bConfigurationValue;}
"bInterfaceNumber" {return par_bInterfaceNumber;}
"bInterfaceClass" {return par_bInterfaceClass;}
"bInterfaceSubClass" {return par_bInterfaceSubClass;}
"count" {return par_count;}

"==" {return op_eq;}
"!=" {return op_neq;}
"<=" {return op_le;}
">=" {return op_ge;}
"<" {return op_lt;}
">" {return op_gt;}*/
%}

%option noyywrap

%%
"allow" {return allow;}
"deny" {return deny;}
"condition" {printf("%s", yytext); return condition;}
"all" {return all;}
"case" {return case_;}
[0-9a-fA-F]+ {return val;}
[a-zA-Z0-9]+ {return param;}
("=="|"!="|"<="|">="|"<"|">") {return op;}
"\n" {return nl;}
<<EOF>> {static unsigned cnt = 0; return cnt++ ? 0 : nl;}
%%

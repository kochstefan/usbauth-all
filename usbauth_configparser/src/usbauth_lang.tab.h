/* A Bison parser, made by GNU Bison 2.7.  */

/* Bison interface for Yacc-like parsers in C
   
      Copyright (C) 1984, 1989-1990, 2000-2012 Free Software Foundation, Inc.
   
   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.
   
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
   
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.
   
   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_USBAUTH_YY_USBAUTH_LANG_TAB_H_INCLUDED
# define YY_USBAUTH_YY_USBAUTH_LANG_TAB_H_INCLUDED
/* Enabling traces.  */
#ifndef USBAUTH_YYDEBUG
# if defined YYDEBUG
#  if YYDEBUG
#   define USBAUTH_YYDEBUG 1
#  else
#   define USBAUTH_YYDEBUG 0
#  endif
# else /* ! defined YYDEBUG */
#  define USBAUTH_YYDEBUG 0
# endif /* ! defined YYDEBUG */
#endif  /* ! defined USBAUTH_YYDEBUG */
#if USBAUTH_YYDEBUG
extern int usbauth_yydebug;
#endif

/* Tokens.  */
#ifndef USBAUTH_YYTOKENTYPE
# define USBAUTH_YYTOKENTYPE
   /* Put the tokens into the symbol table, so that GDB and other debuggers
      know about them.  */
   enum usbauth_yytokentype {
     allow = 258,
     deny = 259,
     condition = 260,
     all = 261,
     case_ = 262,
     val = 263,
     param = 264,
     op = 265,
     op_eq = 266,
     op_neq = 267,
     op_le = 268,
     op_ge = 269,
     op_lt = 270,
     op_gt = 271,
     nl = 272,
     eof = 273,
     par_busnum = 274,
     par_devpath = 275,
     par_idVendor = 276,
     par_idProduct = 277,
     par_bDeviceClass = 278,
     par_bDeviceSubClass = 279,
     par_bConfigurationValue = 280,
     par_bInterfaceNumber = 281,
     par_bInterfaceClass = 282,
     par_bInterfaceSubClass = 283,
     par_count = 284,
     comment = 285,
     comment2 = 286
   };
#endif


#if ! defined USBAUTH_YYSTYPE && ! defined USBAUTH_YYSTYPE_IS_DECLARED
typedef int USBAUTH_YYSTYPE;
# define USBAUTH_YYSTYPE_IS_TRIVIAL 1
# define usbauth_yystype USBAUTH_YYSTYPE /* obsolescent; will be withdrawn */
# define USBAUTH_YYSTYPE_IS_DECLARED 1
#endif

extern USBAUTH_YYSTYPE usbauth_yylval;

#ifdef YYPARSE_PARAM
#if defined __STDC__ || defined __cplusplus
int usbauth_yyparse (void *YYPARSE_PARAM);
#else
int usbauth_yyparse ();
#endif
#else /* ! YYPARSE_PARAM */
#if defined __STDC__ || defined __cplusplus
int usbauth_yyparse (void);
#else
int usbauth_yyparse ();
#endif
#endif /* ! YYPARSE_PARAM */

#endif /* !YY_USBAUTH_YY_USBAUTH_LANG_TAB_H_INCLUDED  */

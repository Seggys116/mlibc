#ifndef _ARPA_TELNET_H
#define _ARPA_TELNET_H

#ifdef __cplusplus
extern "C" {
#endif

/* Telnet protocol special characters */
#define IAC     255  /* Interpret As Command */
#define DONT    254  /* Don't enable option */
#define DO      253  /* Enable option */
#define WONT    252  /* Won't enable option */
#define WILL    251  /* Will enable option */
#define SB      250  /* Subnegotiation begin */
#define GA      249  /* Go ahead */
#define EL      248  /* Erase line */
#define EC      247  /* Erase character */
#define AYT     246  /* Are you there */
#define AO      245  /* Abort output */
#define IP      244  /* Interrupt process */
#define BREAK   243  /* Break */
#define DM      242  /* Data mark */
#define NOP     241  /* No operation */
#define SE      240  /* Subnegotiation end */
#define EOR     239  /* End of record */
#define ABORT   238  /* Abort process */
#define SUSP    237  /* Suspend process */
#define xEOF    236  /* End of file */

/* Telnet options */
#define TELOPT_BINARY           0   /* Binary Transmission */
#define TELOPT_ECHO             1   /* Echo */
#define TELOPT_RCP              2   /* Reconnection */
#define TELOPT_SGA              3   /* Suppress Go Ahead */
#define TELOPT_NAMS             4   /* Approx Message Size Negotiation */
#define TELOPT_STATUS           5   /* Status */
#define TELOPT_TM               6   /* Timing Mark */
#define TELOPT_RCTE             7   /* Remote Controlled Trans and Echo */
#define TELOPT_NAOL             8   /* Output Line Width */
#define TELOPT_NAOP             9   /* Output Page Size */
#define TELOPT_NAOCRD           10  /* Output Carriage-Return Disposition */
#define TELOPT_NAOHTS           11  /* Output Horizontal Tab Stops */
#define TELOPT_NAOHTD           12  /* Output Horizontal Tab Disposition */
#define TELOPT_NAOFFD           13  /* Output Formfeed Disposition */
#define TELOPT_NAOVTS           14  /* Output Vertical Tabstops */
#define TELOPT_NAOVTD           15  /* Output Vertical Tab Disposition */
#define TELOPT_NAOLFD           16  /* Output Linefeed Disposition */
#define TELOPT_XASCII           17  /* Extended ASCII */
#define TELOPT_LOGOUT           18  /* Logout */
#define TELOPT_BM               19  /* Byte Macro */
#define TELOPT_DET              20  /* Data Entry Terminal */
#define TELOPT_SUPDUP           21  /* SUPDUP */
#define TELOPT_SUPDUPOUTPUT     22  /* SUPDUP Output */
#define TELOPT_SNDLOC           23  /* Send Location */
#define TELOPT_TTYPE            24  /* Terminal Type */
#define TELOPT_EOR              25  /* End of Record */
#define TELOPT_TUID             26  /* TACACS User Identification */
#define TELOPT_OUTMRK           27  /* Output Marking */
#define TELOPT_TTYLOC           28  /* Terminal Location Number */
#define TELOPT_3270REGIME       29  /* Telnet 3270 Regime */
#define TELOPT_X3PAD            30  /* X.3 PAD */
#define TELOPT_NAWS             31  /* Negotiate About Window Size */
#define TELOPT_TSPEED           32  /* Terminal Speed */
#define TELOPT_LFLOW            33  /* Remote Flow Control */
#define TELOPT_LINEMODE         34  /* Linemode */
#define TELOPT_XDISPLOC         35  /* X Display Location */
#define TELOPT_OLD_ENVIRON      36  /* Old Environment Variables */
#define TELOPT_AUTHENTICATION   37  /* Authentication */
#define TELOPT_ENCRYPT          38  /* Encryption */
#define TELOPT_NEW_ENVIRON      39  /* New Environment Variables */
#define TELOPT_EXOPL            255 /* Extended-Options-List */

/* Telnet sub-option qualifiers */
#define TELQUAL_IS      0   /* Option is... */
#define TELQUAL_SEND    1   /* Send option */
#define TELQUAL_INFO    2   /* Informational */
#define TELQUAL_REPLY   2   /* Reply to option request */
#define TELQUAL_NAME    3   /* Name */

/* Environment variable option sub-option qualifiers */
#define NEW_ENV_VAR     0   /* Variable */
#define NEW_ENV_VALUE   1   /* Value */
#define ENV_ESC         2   /* Escape */
#define ENV_USERVAR     3   /* User variable */

#ifdef __cplusplus
}
#endif

#endif /* _ARPA_TELNET_H */

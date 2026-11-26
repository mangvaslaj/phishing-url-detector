/*From YRA*/ 

#include <stdio.h>

int main() {

    /* shared variables pwede nyo gamitin sa baba mamaya para sa ibang cases*/
    char url[200] = "";                  /* eto yung url na tinype or pinaste ni user
                                            gagamitin mamaya sa history to */
    char lowercaseUrl[200] = "";         /* lower case copy ng url para sa pag uppercase
                                            -tinype ni user */
    int  urlLength = 0;                  /* self-explanatory but kung gaano kahaba url ni user */
    int  dotCount = 0;                   /* dito ko inistore yung number of period sa url */
    int  index = 0;                      /* pang loop-counter */
    int  menuChoice = 0;                 /* yung choice ni user kung pinili kaba or dahil nandyan ka lang */

    /* mga variables na ginamit ni vincent at saka mga dinagdag ko */
    int flushedChar = '\n';              /* panglinis ng natirang input. int to
                                            hindi char, kasi yung getchar() pwedeng
                                            magbalik ng EOF (-1) pag wala nang
                                            mababasa, tas di kaya ng char ang -1.
                                            pag char ginamit mo, infinite loop
                                            mangyayari. */

    do {
        printf("\n==========================================\n");
        printf("        PHISHING URL DETECTOR\n");
        printf("==========================================\n");
        printf(" 1. Check a URL\n");
        printf(" 2. View scan history\n");
        printf(" 3. View statistics\n");
        printf(" 4. Clear history\n");
        printf(" 5. Exit\n");
        printf("==========================================\n");
        printf("Enter your choice (1-5): ");

        /* babasahin yung choice ni user. pag di number yung tinype,
           gawing 0 para invalid tas di magcrash */
        if (scanf("%d", &menuChoice) != 1) {
            menuChoice = 0;
        }

        /* lilinisin yung natira sa input line, kasama yung enter
           key. pag di to nilinis, mababasa sya sa next prompt
           tas magulo na. kasi binabasa ni scanf() yung \n <- eto yung
           pag nag press ng enter si user para mag continue yung program */
        flushedChar = getchar();
        while (flushedChar != '\n' && flushedChar != EOF) {
            flushedChar = getchar();
        }

        switch (menuChoice) {
            case 1: {


                char inputLine[2048];        /* eto yung buong line na pinaste ni user */
                int  lineLength = 0;         /* kung gaano kahaba yung inputLine */
                int  readChar = 0;           /* isang char at a time ang basa.
                                                int din to hindi char, same shit
                                                as flushedChar: kasi si getchar()
                                                pwedeng magbalik ng EOF (-1) pag
                                                wala nang mababasa */
                int  charsInUrl = 0;         /* kung gaano kadami yung char sa url */
                int  urlCount = 0;           /* kung pang ilang url na to */
                int  lineTooLong = 0;        /* pag-tarantado yung user kasi pinaste yung encyclopedia */
                int  urlTooLong = 0;         /* pag masyado mahaba url tapos naputol dahil sa limit ng data types */

                printf("\nEnter one or more URL (separate with spaces, commas, or semicolons):\n> ");

                /* taga-bilang kung gaano kadami yung pagkakamali mo sa kanya */
                while ((readChar = getchar()) != '\n' && readChar != EOF) {
                    if (lineLength < 2047) {          /* para sa mga tarantado para robust*/
                        inputLine[lineLength] = (char)readChar;
                        lineLength++;
                    } else {
                        lineTooLong = 1;              /* para pag napuno, tuloy lang ang basa */
                    }
                }
                inputLine[lineLength] = '\0';         /* para to sa data type limit*/

                if (lineTooLong) {
                    printf("  Warning: the input was too long and has been cut off.\n");
                }

                /* eto yung pang basa ng char ule if more than one yung url */
                for (index = 0; ; index++) {
                    int isSeparator = 0;

                    if (inputLine[index] == ' '  || inputLine[index] == '\t' ||
                        inputLine[index] == '\r' || inputLine[index] == ','  ||
                        inputLine[index] == ';'  || inputLine[index] == '\0') {
                        isSeparator = 1;
                    }

                    if (isSeparator) {
                        if (charsInUrl > 0) {         /* eto naman if pag may nabuo na url sa tinype ni user */
                            url[charsInUrl] = '\0';    /* para to sa data type limit ule */
                            urlCount++;
                            printf("\n--- URL #%d: %s ---\n", urlCount, url);

                            if (urlTooLong) {
                                printf("  Warning: this URL was too long and has been cut off.\n");
                            }

                            /*  eto yung taga ng lowercase copy nung input ni user if url and taga bilang din nung
                                period sa url. Bakit may ganito Yra? gagamitin natin yung copy sa searching tapos
                                yung original gagamitin ni joshua sa history para di na o-overwrite yung input
                                ni user */
                            dotCount = 0;
                            for (urlLength = 0; url[urlLength] != '\0'; urlLength++) {
                                if (url[urlLength] >= 'A' && url[urlLength] <= 'Z') {
                                    lowercaseUrl[urlLength] = url[urlLength] + 32;
                                } else {
                                    lowercaseUrl[urlLength] = url[urlLength];
                                }
                                if (url[urlLength] == '.') {
                                    dotCount++;
                                }
                            }
                            lowercaseUrl[urlLength] = '\0'; 

                            /* basahin nyo nalang malaki na kayo*/
                            if (urlLength < 4) {
                                printf("  Invalid: the URL is too short.\n");
                            } else if (dotCount == 0) {
                                printf("  Invalid: a URL needs at least one dot.\n");
                            } else if (url[0] == '.' || url[urlLength - 1] == '.') {
                                printf("  Invalid: a URL cannot start or end with a dot.\n");
                            } else {
                                printf("  Valid.\n");
                                /* jaynard at jason dito nyo lagay yung phishing checks
                                    para pag gagamitin, ready to use na siya dito:
                                 *
                                 *   url[]           - exact na type ni user.
                                 *                     pang display to.
                                 *   lowercaseUrl[]  - same letters, puro lowercase.
                                 *                     pang search to.
                                 *   urlLength       - kung gaano kahaba url
                                 *   dotCount        - ilan yung '.' sa url
                                 *
                                 * if mag check kayo, "may ganito bang word "X"
                                 * yung url", hanapin nyo sa -> lowercaseUrl[]
                                 * wag sa -> url[]. kasi pag sa url[]
                                 * kayo naghanap, yung PAYPAL.COM dadaan lang
                                 * nang dadaan sa filter nyo. */
                            }

                            charsInUrl = 0;
                            urlTooLong = 0;            /* reset para sa susunod na URL */
                        }

                        if (inputLine[index] == '\0') {
                            break;                     /* tigil na natin to, di na kita nakikita sa future ko */
                        }
                    } else {
                        if (charsInUrl < 199) {
                            url[charsInUrl] = inputLine[index];
                            charsInUrl++;
                        } else {
                            urlTooLong = 1;            /* pag napuno, pang flag */
                        }
                    }
                }

                if (urlCount == 0) {
                    printf("  No URLs were found in the input.\n");
                } else {
                    printf("\nFinished checking %d URL(s).\n", urlCount);
                }
                break;     /* break na tayo */
            }

            /* dito yung ibang case ng red horse */

        }  /* <--- closing bracket ng switch para di malito HAHAHA*/

    } while (menuChoice != 5);   /* para umikot ka lang sa mundo nya */

    return 0;
}

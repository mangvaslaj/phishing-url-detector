/*From YRA*/ 

#include <stdio.h>
#include <string.h>   

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
    int  scanfResult = 0;                /* resulta ng scanf: 1 = may nabasa,
                                            0 = hindi number, EOF = wala nang input */
    char history[100][200];      /* mga URL na na-scan na */
    int  historyStatus[100];     /* resulta ng bawat URL: 1 = Valid, 0 = Invalid */
    int  historyCount = 0;               /* ilan na ang naka-save ngayon */

    /* mga variables na ginamit ni vincent at saka mga dinagdag ko */
    int flushedChar = '\n';              /* panglinis ng natirang input. int to
                                            hindi char, kasi yung getchar() pwedeng
                                            magbalik ng EOF (-1) pag wala nang
                                            mababasa, tas di kaya ng char ang -1.
                                            pag char ginamit mo, infinite loop
                                            mangyayari. */
    int susWordsCount = 0;                                  /* yung count ng suspicious words, 
                                                            0 kasi wala pang na detect maiiba value kapag may nahanap */

    char *susWords[] = {                                     // dito nakalagay ang mga predefined suspicious words(primitve)
        "login",
        "verify",
        "free",
        "claim",
        "winner",
        "password",
        "account",
        "bank",
        "promo",
        "update",
        "secure",
        "safe",
        "promotion",
        "secret",
        "exclusive",
        "urgent",
        "hack",
    };

    int wordCount = sizeof(susWords) / sizeof(susWords[0]); /* this defines yung "int susWords" dito huhugot ang 
                                                            detector ng number kapag magssearch sya ng predefined suspicious words.*/
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

        scanfResult = scanf("%d", &menuChoice);

        /* pag EOF (walang mababasa, e.g. Ctrl+D / Ctrl+Z), lumabas na
           para hindi mag-infinite loop */
        if (scanfResult == EOF) {
            menuChoice = 5;
        } else if (scanfResult != 1) {
            menuChoice = 0;      /* hindi number ang tinype */
        }

        flushedChar = getchar();
        while (flushedChar != '\n' && flushedChar != EOF) {
            flushedChar = getchar();
        }

        /* 1-5 lang ang pwede. kung hindi, ulitin ang menu */
        if (menuChoice < 1 || menuChoice > 5) {
            printf("\n  Invalid choice. Please enter a number from 1 to 5.\n");
            continue;            /* tatalon sa while condition, tapos ulit sa menu */
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
                int  isValid = 0;            
                int  shiftIndex = 0; 

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
                            isValid = 0;
                            /* basahin nyo nalang malaki na kayo*/
                            if (urlLength < 4) {
                                printf("  Invalid: the URL is too short.\n");
                            } else if (dotCount == 0) {
                                printf("  Invalid: a URL needs at least one dot.\n");
                            } else if (url[0] == '.' || url[urlLength - 1] == '.') {
                                printf("  Invalid: a URL cannot start or end with a dot.\n");
                            } else {
                                printf("  Valid.\n");
                                isValid = 1;
                                if (strchr(inputLine,'-') != NULL) {
                                    printf("Warning: Link Contains Hypen\n");
                                }
                                
                                if (strchr(inputLine, '@') != NULL) {
                                    printf("Warning: Link Contains @\n");
                                }

                                susWordsCount = 0; // eto taga reset ng counter para each link may sariling number di nagpapatong

                                for (int i = 0; i < wordCount; i++) {

                                    if (strstr(lowercaseUrl, susWords[i]) != NULL) {
                                        susWordsCount++;
                                    }
                                }
                                
                                if (susWordsCount <= 0) {
                                        printf("  No Suspicous Word Found\n");
                                }
                                else if(susWordsCount <= 2){
                                    printf("  Danger Level: Low\n");
                                    printf("  Suspicious word detected: %d\n", susWordsCount);
                                }
                                else if(susWordsCount <= 3){
                                    printf("  Danger Level: Medium\n");
                                    printf("  Suspicious word detected: %d\n", susWordsCount);
                                }
                                else if(susWordsCount <= 6){
                                    printf("  Danger Level: High\n");
                                    printf("  Suspicious word detected: %d\n", susWordsCount);
                                }
                                else {
                                    printf("  Danger Level: Critical\n");
                                    printf("  Suspicious word detected: %d\n", susWordsCount);
                                }

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
                            if (historyCount == 100) {
                                for (shiftIndex = 1; shiftIndex < 100; shiftIndex++) {
                                    strcpy(history[shiftIndex - 1], history[shiftIndex]);
                                    historyStatus[shiftIndex - 1] = historyStatus[shiftIndex];
                                }
                                historyCount--;
                            }
                            strcpy(history[historyCount], url);
                            historyStatus[historyCount] = isValid;
                            historyCount++;
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
            case 2: {
                printf("\n==========================================\n");
                printf("             SCAN HISTORY\n");
                printf("==========================================\n");

                if (historyCount == 0) {
                    printf("  No scans yet. Go to Option 1 to add URL.\n");
                } else {
                    for (index = 0; index < historyCount; index++) {
                        printf("  %3d. %-45s [%s]\n",
                               index + 1,
                               history[index],
                               historyStatus[index] ? "Valid" : "Invalid");
                    }
                    printf("------------------------------------------\n");
                    printf("  Total records: %d\n", historyCount);
                }
                break;
            }
            /* NEW: CASE 3 - View statistics */
            case 3: {
                int validCount = 0;          /* ilan yung Valid */
                int invalidCount = 0;        /* ilan yung Invalid */

                printf("\n==========================================\n");
                printf("              STATISTICS\n");
                printf("==========================================\n");

                if (historyCount == 0) {
                    printf("  No data yet. Go to Option 1 to add URL.\n");
                } else {
                    for (index = 0; index < historyCount; index++) {
                        if (historyStatus[index] == 1) {
                            validCount++;
                        } else {
                            invalidCount++;
                        }
                    }

                    printf("  Total URLs scanned : %d\n", historyCount);
                    printf("  Valid URLs         : %d (%.1f%%)\n",
                           validCount, validCount * 100.0 / historyCount);
                    printf("  Invalid URLs       : %d (%.1f%%)\n",
                           invalidCount, invalidCount * 100.0 / historyCount);
                }
                break;
            }
            case 4: {
                int answer = 0;              /* y or n ni user */

                if (historyCount == 0) {
                    printf("\n  History is already empty.\n");
                } 
                else {
                    printf("\n  Delete all %d record(s)? (y/n): ", historyCount);
                    answer = getchar();

                    /* linisin yung natirang input, pero kung Enter na agad
                       ang tinype (answer == '\n'), wala nang lilinisin */
                    if (answer != '\n' && answer != EOF) {
                        flushedChar = getchar();
                        while (flushedChar != '\n' && flushedChar != EOF) {
                            flushedChar = getchar();
                        }
                    }

                    if (answer == 'y' || answer == 'Y') {
                        historyCount = 0;    /* hindi na kailangan burahin isa-isa,
                                                babalik lang sa 0 yung counter, tapos
                                                mao-overwrite na yung luma */
                        printf("  History cleared.\n");
                    } else {
                        printf("  Cancelled. History was not deleted.\n");
                    }
                }
                break;
            }
            case 5:
                printf("\nExiting the program. Goodbye!\n");
                break;
        }  /* <--- closing bracket ng switch para di malito HAHAHA*/

    } while (menuChoice != 5);   /* para umikot ka lang sa mundo nya */

    return 0;
}

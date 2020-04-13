/**
 *			P I N G
 *
 * Using the Internet Control Message Protocol (ICMP) "ECHO" facility to:
 *  - provide network point-to-point statistics concerning packet loss
 *    and round time trip time
 *  - find the route packets take to reach a network host (and display
 *    network statistics about each host)
 *
 * Hack by Francois Gouget (fgouget@free.fr), based on:
 *  - the ping sample provided with the ICMP libraries (author unknown)
 *  - the FreeBSD ping interface
 *  - the FreeBSD traceroute interface
 *  - bing for these comments
 *
 * Comments and bug reports welcome !
 *


  Re-hacked by Eli Fulkerson from a normal traceroute program into the XML-output variety.

*/

#include <stdio.h>
#include <limits.h>
#include <time.h>

#include <windows.h>

#include <ipexport.h>
#include <icmpapi.h>

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")



/* ------------------------------------
 *
 * Application parameters
 *
 * ----------------------------------*/

 /**
  * The application name for error messages.
  */
#define PING_NAME               "ping"

  /**
   * How big is an ICMP header.
   */
#define ICMP_HEADER_SIZE        8



   /* ------------------------------------
    *
    * Options defaults
    *
    * ----------------------------------*/


    /**
     * Send ICMP packets ad infinitum.
     */
#define DEFAULT_OPT_C_VALUE     -1

     /**
      * Wait 1 seconde between ICMP packets.
      */
#define DEFAULT_OPT_I_VALUE      1

      /**
       * Same as for TCP.
       */
#define DEFAULT_OPT_M_VALUE     30

       /**
        * Add 56 bytes of data which makes for a 64 bytes ICMP packet.
        */
#define DEFAULT_OPT_S_VALUE     56

        /**
         * Wait for a reply for 5 seconds.
         */
#define DEFAULT_OPT_W_VALUE     3000L

         /**
          * Patterns are at most 16 bytes long.
          */
#define OPT_P_MAX_SIZE          16



          /* ------------------------------------
           *
           * Options flags and values.
           *
           * ----------------------------------*/

           /**
            * A bit field for storing boolean options.
            * Note that in some cases the field is not a boolean and this variable
            * simply stores whether the option has been used while the actual value is
            * stored elswhere.
            */
unsigned short options = 0;

#define F_COUNT         0x0001
#define F_INTERVAL      0x0002
#define F_MAXTTL        0x0004
#define F_NUMERIC       0x0008
#define F_PATTERN       0x0010
#define F_QUIET         0x0020
#define F_DATASIZE      0x0040
#define F_TRACE         0x0080
#define F_TIMEOUT       0x0100
#define F_RANDOMFILL    0x0200

int opt_c = DEFAULT_OPT_C_VALUE;
int opt_i = DEFAULT_OPT_I_VALUE;
int opt_m = DEFAULT_OPT_M_VALUE;
int opt_p_length;
unsigned char opt_p_pattern[16];
int opt_s = DEFAULT_OPT_S_VALUE;
int opt_w = DEFAULT_OPT_W_VALUE;

/*
 * Some global variables
 */
HANDLE hIcmp;
unsigned long count;
unsigned short icmp_data_size = 0;
unsigned char* icmp_data = NULL;
unsigned char reply_buffer[10000];
LARGE_INTEGER ticks_freq;
struct icmp_echo_reply* icmp_reply;


/* ------------------------------------
 *
 * Functions implementing "non-core" functionalities of ping
 *
 * ----------------------------------*/

 /**
  * Handles the console events such as CTRL_C_EVENT.
  * We tell the doPing function to stop by setting the count variable to 1.
  * Because this handler is run in its own thread count must be modified
  * using InterlockedIncrement and InterlockedDecrement.
  *
  * @param dwCtrlType the code of the console event
  * @return TRUE if the event was handled, FALSE otherwise
  */
BOOL WINAPI ConsoleCtrlHandler(DWORD dwCtrlType)
{
    if (dwCtrlType == CTRL_C_EVENT) {
        if (!(options & F_TRACE)) {
            count = 0;
            return TRUE;
        }
        else
            return FALSE;
    }
    else
        return FALSE;
}

/**
 * Converts a string to an IP address. The address may be specified
 * either as a host name or as the IP address in "dotted" format.
 *
 * @param host_string the host name / address
 * @return the host's IP address if successful, INADDR_NONE otherwise
 */
unsigned int HostString2Addr(char* host_string)
{
    unsigned int host_addr;

    host_addr = inet_addr(host_string);
    if (host_addr == INADDR_NONE) {
        struct hostent* he;

        he = gethostbyname(host_string);
        if (he == NULL) {
            fprintf(stderr, "%s: unknown host %s\n", PING_NAME, host_string);
        }
        else if (he->h_addrtype != AF_INET) {
            fprintf(stderr, "%s: host %s is not in the AF_INET domain\n",
                PING_NAME, host_string);
        }
        else {
            memcpy(&host_addr, he->h_addr, sizeof(host_addr));
        }
    }
    return host_addr;
}

/**
 * Returns a pointer to a string suitable for representing the host's
 * address. If the options parameter contains the F_NUMERIC option
 * HostAddr2String will not attempt to get the host name so that the
 * returned string will only contain the host adress.
 *
 * @param host_addr the host IP address
 * @param options the options value
 * @return a pointer to a static area containing the string to display for
 *         that host
 */
char* HostAddr2String(int host_addr, int options)
{
    static char host_string[15 + 1 + 1 + 64 + 1 + 1];
    char* ip_str;

    ip_str = inet_ntoa(*((struct in_addr*) & host_addr));
    if (options & F_NUMERIC) {
        //strncpy(host_string,ip_str,sizeof(host_string));
        printf("\t\t<hostname>!Unknown!</hostname>\n\t\t<ip>%s</ip>\n", ip_str);

    }
    else {
        struct hostent* he;

        he = gethostbyaddr((char*)&host_addr, sizeof(host_addr), AF_INET);
        if (he != NULL)
            //_snprintf(host_string,sizeof(host_string),"%s (%s)", he->h_name,ip_str);
            printf("\t\t<hostname>%s</hostname>\n\t\t<ip>%s</ip>\n", he->h_name, ip_str);

        else
            //_snprintf(host_string,sizeof(host_string),"<unknown> (%s)", ip_str);
            printf("\t\t<hostname>!Unknown!</hostname>\n\t\t<ip>%s</ip>\n", ip_str);
    }
    //host_string[sizeof(host_string)-1]='\0';
    //return host_string;

}


/* ------------------------------------
 *
 * Core functions implementing the actual ping and trace algorithms
 *
 * ----------------------------------*/


 /**
  * Sends ICMP echo Request packets with increasing TTLs to discover
  * the list of hosts the packets are routed through on their way to
  * the target host.
  *
  * @param target_addr internet address of the target host
  * @param target_string string to display for that host
  */
void doTrace(unsigned int target_addr, char* target_string)
{
    int status;
    int hop, probe, nb_probes;
    unsigned int gateway_addr;
    struct ip_option_information ip_opts;

    /*printf("traceroute to %s, %d hops max, %d byte packets\n",
           target_string,opt_m,ICMP_HEADER_SIZE+opt_s);*/

    printf("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<urlset xmlns=\"http://www.elifulkerson.com/projects/xmlroute.php\">\n");
    printf("<traceroute>\n\t<target>%s</target>\n", target_string);

    /* Prepare the IP options */
    memset(&ip_opts, 0, sizeof(ip_opts));

    nb_probes = (opt_c > 0 ? opt_c : 3);
    for (hop = 1;hop < opt_m;hop++) {
        double rtt, min_rtt, sum_rtt, max_rtt;
        int nb_rtt_samples, nb_rtt_stats;
        LARGE_INTEGER start, stop;

        //printf("%2d  ",hop);
        printf("\t<hop>\n\t\t<count>%d</count>\n", hop);

        ip_opts.Ttl = hop;
        gateway_addr = INADDR_NONE;

        /* No we must send some probes with the specified TTL */
        nb_rtt_samples = nb_rtt_stats = 0;
        min_rtt = 86400000.0; /* One day */
        sum_rtt = max_rtt = 0.0;
        for (probe = 0;probe < nb_probes;probe++) {
            //GenerateData(0);
            QueryPerformanceCounter(&start);
            status = IcmpSendEcho(hIcmp,
                target_addr,
                (LPVOID)icmp_data,
                icmp_data_size,
                &ip_opts,
                reply_buffer,
                sizeof(reply_buffer),
                opt_w);
            QueryPerformanceCounter(&stop);

            /* Report this probe's result */
            if (status == 0) {
                status = GetLastError();
                //if (status!=IP_REQ_TIMED_OUT)
                    /*fprintf(stderr,"An error (%d) occurred while sending the ICMP Echo Request to %s\n",
                            status,target_string);*/
               // printf("\t\t<ip>error</ip>\n\t</hop>\n</traceroute>\n</urlset>\n");
                //return;
                //if (!(options & F_QUIET))
                //    printf("  * ms  ");
            }
            else {
                if (gateway_addr == INADDR_NONE) {
                    gateway_addr = icmp_reply->Address;
                }
                else if (gateway_addr != icmp_reply->Address) {
                    /*fprintf(stderr,"Multiple gateways answered for hop %d: %s\n",
                            hop,HostAddr2String(icmp_reply->Address,options));*/
                }

                /* compute the RTT, see doPing for explanations */
                if ((ticks_freq.QuadPart == 0) ||
                    ((rtt = ((double)((stop.QuadPart - start.QuadPart) * 1000)) / ticks_freq.QuadPart) >
                        (double)(icmp_reply->RoundTripTime + 2))) {
                    rtt = (double)(icmp_reply->RoundTripTime + 1);
                }

                if (options & F_QUIET) {
                    if (rtt < (double)(icmp_reply->RoundTripTime + 2)) {
                        /* Update the statistics */
                        if (rtt < min_rtt)
                            min_rtt = rtt;
                        if (rtt > max_rtt)
                            max_rtt = rtt;
                        sum_rtt += rtt;
                        nb_rtt_stats++;
                    }
                    nb_rtt_samples++;
                }
                else {
                    //printf("%.3f ms  ",rtt);
                    printf("\t\t<ms>%.3f</ms>\n", rtt);
                }
            }
        }
        /* Display statistics for that host */
        //if (options & F_QUIET)
        if (0) {
            printf("sent %d received %d loss %d%% ",
                nb_probes, nb_rtt_samples, (nb_probes - nb_rtt_samples) * 100 / nb_probes);
            if (nb_rtt_samples > 0) {
                printf("rtt %.3f/%.3f/%.3f ms  ",
                    min_rtt, ((float)sum_rtt) / nb_rtt_stats, max_rtt);
            }
            else {
                printf("rtt */*/* ms  ");
            }
        }
        if (gateway_addr != INADDR_NONE)
            //printf("\t\t<ip>%s</ip>\n\t</hop>\n",HostAddr2String(gateway_addr,options));
            HostAddr2String(gateway_addr, options);
        printf("\t</hop>\n");

        if (gateway_addr == target_addr)
            break;
        Sleep(1000 * opt_i);
    }
    printf("</traceroute>\n</urlset>\n");
}
/* ------------------------------------
 *
 * Main program
 *
 * ----------------------------------*/

 /**
  * Parses the ping parameters and calls doPing or doTrace as appropriate.
  * For the tool usage, see comments at the beginning.
  *
  * @param argc number of command-line options
  * @param argv command line options
  * @return 0 if sucessful, 2 for a usage error and 1 otherwise
  */
int main(int argc, char** argv)
{
    int retcode;
    WSADATA wsaData;
    char** arg;

    if (argc < 2)
        goto usage;

    /* Initialisation */
    if (WSAStartup(MAKEWORD(1, 1), &wsaData)) {
        fprintf(stderr, "%s: You must use Winsock 1.1 or compatible\n", PING_NAME);
        goto error;
    }
    hIcmp = IcmpCreateFile();
    srand(time(NULL));
    /* Give a higher priority so that ping has better
     * chances not to be delayed when measuring the RTT.
     */
    SetPriorityClass(GetCurrentProcess(), HIGH_PRIORITY_CLASS);
    QueryPerformanceFrequency(&ticks_freq);
    icmp_reply = (struct icmp_echo_reply*)reply_buffer;

    /* Install the ^C handler */
    SetConsoleCtrlHandler(&ConsoleCtrlHandler, TRUE);

    /* Parse the parameters and do the pinging and traceing */
    retcode = 0;
    arg = argv + 1;

    while (*arg != NULL) {
        if ((*arg)[0] == '-') {
            /* Change some option value */
            switch ((*arg)[1]) {
            case 'c':
                /* Sets the number of messages to send to the
                 * target host. Only valid in ping mode.
                 */
                arg++;
                if (sscanf_s(*arg, "%d", &opt_c) != 1)
                    goto usage;
                if (opt_c < 0)
                    opt_c = DEFAULT_OPT_C_VALUE;
                options |= F_COUNT;
                break;
            case 'd':
                /* Sets the SO_DEBUG option on the socket used  by ping.
                 * => Not implemented. Since we don't use sockets this
                 *    option is rather meaningless. Maybe we could try to
                 *    print debug messages.
                 */
                break;
            case 'f':
                /* Causes ping to flood the target host sending EchoRequest
                 * at a rate of 100 per second or as fast as they come back
                 * whichever is more.
                 * => Cannot be implemented with this ICMP interface because
                 *    IcmpSendEchoRequest will block until it receives an
                 *    answer (maybe using multiple thread would provide an
                 *    awkward solution).
                 *    Note though that setting the -i option to 0 is roughly
                 *    equivalent on fast networks.
                 */
                break;
            case 'i':
                /* Sets the interval between two echo requests. */
                arg++;
                if (sscanf_s(*arg, "%d", &opt_i) != 1)
                    goto usage;
                if (opt_i < 0)
                    opt_i = DEFAULT_OPT_I_VALUE;
                options |= F_INTERVAL;
                break;
            case 'l':
                /* Causes ping to send the specified number of packets before
                 * waiting.
                 * => Cannot be implemented with this ICMP interface because
                 *    IcmpSendEchoRequest will block until it receives an
                 *    answer (maybe using multiple thread would provide an
                 *    awkward solution).
                 */
                break;
            case 'm':
                /* Sets the TTL to use.
                 */
                arg++;
                if (sscanf_s(*arg, "%d", &opt_m) != 1)
                    goto usage;
                if (opt_m < 0)
                    opt_m = DEFAULT_OPT_M_VALUE;
                options |= F_MAXTTL;
                break;
            case 'n':
                /* Do not attempt to translate symbolic names for host
                 * addresses
                 */
                options |= F_NUMERIC;
                break;

            case 'q':
                /* Quiet option: only display a summary at the end.
                 * Only valid in ping mode.
                 */
                options |= F_QUIET;
                break;
            case 'R':
                /*
                 * Record route.
                 * => Could be implemented by manually adding the proper
                 *    IP option fields and by manually decoding the answer.
                 */
                break;
            case 'r':
                /* Bypass normal routing.
                 * => Not implemented.
                 *    I'm not sure whether this could be implemented
                 */
                break;

            case 't':
                /*
                 * Switch to traceroute mode.
                 */
                options |= F_TRACE;
                break;
            case 'v':
                /*
                 * Print messages other than EchoResponse
                 * => Not implemented
                 *    The implementation requires parsing the IP options data
                 *    contained in the icmp_reply
                 */
                break;
            case 'w':
                /*
                 * Sets the time to wait for a response to an Echo Request
                 */
                arg++;
                if (sscanf_s(*arg, "%d", &opt_w) != 1)
                    goto usage;
                if (opt_w < 0)
                    opt_w = DEFAULT_OPT_W_VALUE;
                options |= F_TIMEOUT;
                break;
            case 'z':
                /*
                 * Fills the ICMP packets with random data
                 */
                options = (options & ~F_PATTERN) | F_RANDOMFILL;
                break;
            }
        }
        else {
            unsigned int host_addr;

            options |= F_TRACE;
            //options|=F_NUMERIC;
            opt_i = 0;
            options |= F_INTERVAL;


            /* Get the target host address */
            host_addr = HostString2Addr(*arg);
            if (host_addr == INADDR_NONE)
                retcode = 1;
            else if (options & F_TRACE)
                doTrace(host_addr, *arg);

        }
        arg++;
    }

    /* Do some cleanup */
    IcmpCloseHandle(hIcmp);
    WSACleanup();
    free(icmp_data);

end:
    return retcode;

error:
    retcode = 1;
    goto end;

usage:
    fprintf(stderr, "********************************************************\n");
    fprintf(stderr, "* xmlroute.exe - written by Eli Fulkerson, Oct 2006    *\n");
    fprintf(stderr, "* Please visit http://www.elifulkerson.com for updates.*\n");
    fprintf(stderr, "********************************************************\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "This is an implementation of traceroute which presents its output as xml.\n");
    fprintf(stderr, "It is intended for use behind the scenes, for instance in network monitoring\n");
    fprintf(stderr, "scripts.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "In order to reduce ambiguity, this utility stops tracerouting (and closes the\n");
    fprintf(stderr, "xml) as soon as it encounters a timeout.\n");
    fprintf(stderr, "\n");
    fprintf(stderr, "Usage: xmlroute [-n] [-c count] [-i wait] host\n");
    fprintf(stderr, "       -i sets wait in seconds\n");
    fprintf(stderr, "       -n turns off name resoution\n");
    fprintf(stderr, "       -c sets the number of times to probe each node\n");
    retcode = 2;
    goto end;
}

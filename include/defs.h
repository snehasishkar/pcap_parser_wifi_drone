/*
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * is provided AS IS, WITHOUT ANY WARRANTY; without even the implied
 * warranty of MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, and
 * NON-INFRINGEMENT.  See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston,
 * MA 02110-1301, USA.
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
 */

#ifndef DEFS_H_
#define DEFS_H_

#include <sys/ioctl.h>
#include "../include/eapol.h"
#include "../include/common.h"

/* some constants */

#define REFRESH_RATE 100000 /* default delay in us between updates */
#define DEFAULT_HOPFREQ 250 /* default delay in ms between channel hopping */
#define DEFAULT_CWIDTH 20 /* 20 MHz channels by default */

#define NB_PWR 5 /* size of signal power ring buffer */
//#define NB_PRB 10 /* size of probed ESSID ring buffer */
#define NB_PRB 1000 /* size of probed ESSID ring buffer */

#define MAX_CARDS 8 /* maximum number of cards to capture from */

#define STD_OPN 0x0001
#define STD_WEP 0x0002
#define STD_WPA 0x0004
#define STD_WPA2 0x0008

#define STD_FIELD (STD_OPN | STD_WEP | STD_WPA | STD_WPA2)

#define ENC_WEP 0x0010
#define ENC_TKIP 0x0020
#define ENC_WRAP 0x0040
#define ENC_CCMP 0x0080
#define ENC_WEP40 0x1000
#define ENC_WEP104 0x0100
#define ENC_GCMP 0x4000

#define ENC_FIELD                                                              \
	(ENC_WEP | ENC_TKIP | ENC_WRAP | ENC_CCMP | ENC_WEP40 | ENC_WEP104         \
	 | ENC_GCMP)

#define AUTH_OPN 0x0200
#define AUTH_PSK 0x0400
#define AUTH_MGT 0x0800

#define AUTH_FIELD (AUTH_OPN | AUTH_PSK | AUTH_MGT)

#define STD_QOS 0x2000

#define QLT_TIME 5
#define QLT_COUNT 25

#define SORT_BY_NOTHING 0
#define SORT_BY_BSSID 1
#define SORT_BY_POWER 2
#define SORT_BY_BEACON 3
#define SORT_BY_DATA 4
#define SORT_BY_PRATE 5
#define SORT_BY_CHAN 6
#define SORT_BY_MBIT 7
#define SORT_BY_ENC 8
#define SORT_BY_CIPHER 9
#define SORT_BY_AUTH 10
#define SORT_BY_ESSID 11
#define MAX_SORT 11

#define RATES "\x01\x04\x02\x04\x0B\x16\x32\x08\x0C\x12\x18\x24\x30\x48\x60\x6C"

#define PROBE_REQ                                                              \
	"\x40\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xCC\xCC\xCC\xCC\xCC\xCC"         \
	"\xFF\xFF\xFF\xFF\xFF\xFF\x00\x00"

// milliseconds to store last packets
#define BUFFER_TIME 3000

extern int get_ram_size(void);
char *
get_manufacturer(unsigned char mac0, unsigned char mac1, unsigned char mac2);

const unsigned char llcnull[4] = {0, 0, 0, 0};

extern const unsigned long int crc_tbl[256];
extern const unsigned char crc_chop_tbl[256][4];

#define MIN_RAM_SIZE_LOAD_OUI_RAM 32768

int32_t read_pkts = 0;

int32_t abg_chans[]
	= {1,   7,   13,  2,   8,   3,   14,  9,   4,   10,  5,   11,  6,
	   12,  36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,
	   60,  62,  64,  100, 102, 104, 106, 108, 110, 112, 114, 116, 118,
	   120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142, 144, 149,
	   151, 153, 155, 157, 159, 161, 165, 169, 173, 0};

int32_t bg_chans[] = {1, 7, 13, 2, 8, 3, 14, 9, 4, 10, 5, 11, 6, 12, 0};

int32_t a_chans[] = {36,  38,  40,  42,  44,  46,  48,  50,  52,  54,  56,  58,
				 60,  62,  64,  100, 102, 104, 106, 108, 110, 112, 114, 116,
				 118, 120, 122, 124, 126, 128, 132, 134, 136, 138, 140, 142,
				 144, 149, 151, 153, 155, 157, 159, 161, 165, 169, 173, 0};

int32_t * frequencies;

/* linked list of received packets for the last few seconds */
struct pkt_buf
{
	struct pkt_buf * next; /* next packet in list */
	unsigned char * packet; /* packet */
	unsigned short length; /* packet length */
	struct timeval ctime; /* capture time */
};

/* oui struct for list management */
struct oui
{
	char id[9]; /* TODO: Don't use ASCII chars to compare, use unsigned char[3]
				   (later) with the value (hex ascii will have to be converted)
				   */
	char
		manuf[128]; /* TODO: Switch to a char * later to improve memory usage */
	struct oui * next;
};

/* WPS_info struct */
struct WPS_info
{
	unsigned char version; /* WPS Version */
	unsigned char state; /* Current WPS state */
	unsigned char ap_setup_locked; /* AP setup locked */
	unsigned int meth; /* WPS Config Methods */
};

#define MAX_AC_MCS_INDEX 8

/* 802.11n channel information */
struct n_channel_info
{
	char mcs_index; /* Maximum MCS TX index     */
	char sec_channel; /* 802.11n secondary channel*/
	unsigned char short_gi_20; /* Short GI for 20MHz       */
	unsigned char short_gi_40; /* Short GI for 40MHz       */
	unsigned char any_chan_width; /* Support for 20 or 40MHz
									as opposed to only 20 or
									only 40MHz               */
};

/* 802.11ac channel information */
struct ac_channel_info
{
	unsigned char center_sgmt[2];
	/* 802.11ac Center segment 0*/
	unsigned char mu_mimo; /* MU-MIMO support          */
	unsigned char short_gi_80; /* Short GI for 80MHz       */
	unsigned char short_gi_160; /* Short GI for 160MHz      */
	unsigned char split_chan; /* 80+80MHz Channel support */
	unsigned char mhz_160_chan; /* 160 MHz channel support  */
	unsigned char wave_2; /* Wave 2                   */
	unsigned char mcs_index[MAX_AC_MCS_INDEX];
	/* Maximum TX rate          */
};

enum channel_width_enum
{
	CHANNEL_UNKNOWN_WIDTH,
	CHANNEL_3MHZ,
	CHANNEL_5MHZ,
	CHANNEL_10MHZ,
	CHANNEL_20MHZ,
	CHANNEL_22MHZ,
	CHANNEL_30MHZ,
	CHANNEL_20_OR_40MHZ,
	CHANNEL_40MHZ,
	CHANNEL_80MHZ,
	CHANNEL_80_80MHZ,
	CHANNEL_160MHZ
};

/* linked list of detected access points */
struct AP_info
{
	struct AP_info * prev; /* prev. AP in list         */
	struct AP_info * next; /* next  AP in list         */

	time_t tinit, tlast; /* first and last time seen */

	int32_t channel; /* AP radio channel         */
	enum channel_width_enum channel_width; /* Channel width            */
	char standard[3]; /* 802.11 standard: n or ac */
	struct n_channel_info n_channel; /* 802.11n channel info     */
	struct ac_channel_info ac_channel; /* 802.11ac channel info    */
	int32_t max_speed; /* AP maximum speed in Mb/s */
	int32_t avg_power; /* averaged signal power    */
	int best_power; /* best signal power    */
	int32_t power_index; /* index in power ring buf. */
	int32_t power_lvl[NB_PWR]; /* signal power ring buffer */
	int32_t preamble; /* 0 = long, 1 = short      */
	int32_t security; /* ENC_*, AUTH_*, STD_*     */
	int32_t beacon_logged; /* We need 1 beacon per AP  */
	int32_t dict_started; /* 1 if dict attack started */
	int32_t ssid_length; /* length of ssid           */
	float gps_loc_min[5]; /* min gps coordinates      */
	float gps_loc_max[5]; /* max gps coordinates      */
	float gps_loc_best[5]; /* best gps coordinates     */

	unsigned long nb_bcn; /* total number of beacons  */
	unsigned long nb_pkt; /* total number of packets  */
	unsigned long nb_data; /* number of  data packets  */
	unsigned long nb_data_old; /* number of data packets/sec*/
	int32_t nb_dataps; /* number of data packets/sec*/
	struct timeval tv; /* time for data per second */

	unsigned char bssid[6]; /* the access point's MAC   */
	char * manuf; /* the access point's manufacturer */
	unsigned char essid[MAX_IE_ELEMENT_SIZE];
	/* ascii network identifier */
	unsigned long long timestamp;
	/* Timestamp to calculate uptime   */

	unsigned char lanip[4]; /* last detected ip address */
	/* if non-encrypted network */

	unsigned char ** uiv_root; /* unique iv root structure */
	/* if wep-encrypted network */

	int32_t rx_quality; /* percent of captured beacons */
	int32_t fcapt; /* amount of captured frames   */
	int32_t fmiss; /* amount of missed frames     */
	unsigned int last_seq; /* last sequence number        */
	struct timeval ftimef; /* time of first frame         */
	struct timeval ftimel; /* time of last frame          */
	struct timeval ftimer; /* time of restart             */

	char * key; /* if wep-key found by dict */
	int32_t essid_stored; /* essid stored in ivs file? */

	char decloak_detect; /* run decloak detection? */
	struct pkt_buf * packets; /* list of captured packets (last few seconds) */
	char is_decloak; /* detected decloak */

	// This feature eats 48Mb per AP
	int32_t EAP_detected;
	unsigned char * data_root; /* first 2 bytes of data if */
	/* WEP network; used for    */
	/* detecting WEP cloak	  */
	/* + one byte to indicate   */
	/* (in)existence of the IV  */

	int32_t marked;
	int32_t marked_color;
	struct WPS_info wps;
	int32_t SNR;   /*SNR */
	double frequency; /*Frequency of the access-point   */
	double distance;  /*Distance of the access-point from source*/
};
/* linked list of detected clients */
struct ST_info
{
	struct ST_info * prev; /* the prev client in list   */
	struct ST_info * next; /* the next client in list   */
	struct AP_info * base; /* AP this client belongs to */
	time_t tinit, tlast; /* first and last time seen  */
	unsigned long nb_pkt; /* total number of packets   */
	unsigned char stmac[6]; /* the client's MAC address  */
	char * manuf; /* the client's manufacturer */
	int32_t probe_index; /* probed ESSIDs ring index  */
	char probes[NB_PRB][MAX_IE_ELEMENT_SIZE];
	/* probed ESSIDs ring buffer */
	int32_t ssid_length[NB_PRB]; /* ssid lengths ring buffer  */
	int32_t power; /* last signal power         */
	int32_t best_power; /* best signal power    */
	int32_t rate_to; /* last bitrate to station   */
	int32_t rate_from; /* last bitrate from station */
	struct timeval ftimer; /* time of restart           */
	int32_t missed; /* number of missed packets  */
	unsigned int lastseq; /* last seen sequence number */
	struct WPA_hdsk wpa; /* WPA handshake data        */
	int32_t qos_to_ds; /* does it use 802.11e to ds */
	int32_t qos_fr_ds; /* does it receive 802.11e   */
	int32_t channel; /* Channel station is seen   */
	float gps_loc_min[5]; /* min gps coordinates      */
	float gps_loc_max[5]; /* max gps coordinates      */
	float gps_loc_best[5]; /* best gps coordinates     */
	int32_t SNR;   /*SNR */
	double frequency; /*Frequency of the station  */
	double distance; /*Distance of the station from source*/
	/*  Not used yet		  */
};

/* linked list of detected macs through ack, cts or rts frames */

struct NA_info
{
	struct NA_info * prev; /* the prev client in list   */
	struct NA_info * next; /* the next client in list   */
	time_t tinit, tlast; /* first and last time seen  */
	unsigned char namac[6]; /* the stations MAC address  */
	int32_t power; /* last signal power         */
	int32_t channel; /* captured on channel       */
	int32_t ack; /* number of ACK frames      */
	int32_t ack_old; /* old number of ACK frames  */
	int32_t ackps; /* number of ACK frames/s    */
	int32_t cts; /* number of CTS frames      */
	int32_t rts_r; /* number of RTS frames (rx) */
	int32_t rts_t; /* number of RTS frames (tx) */
	int32_t other; /* number of other frames    */
	struct timeval tv; /* time for ack per second   */
};
/* bunch of global stuff */

struct globals
{
	struct AP_info *ap_1st, *ap_end;
	struct ST_info *st_1st, *st_end;
	struct NA_info *na_1st, *na_end;
	struct oui * manufList;

	unsigned char prev_bssid[6];
	unsigned char f_bssid[6];
	unsigned char f_netmask[6];
	char ** f_essid;
	int32_t f_essid_count;
#ifdef HAVE_PCRE
	pcre * f_essid_regex;
#endif
	char * dump_prefix;
	char * keyout;
	char * f_cap_name;

	int32_t f_index; /* outfiles index       */
	FILE * f_txt; /* output csv file      */
	FILE *f_json; /* output json file     */
	FILE * f_kis; /* output kismet csv file      */
	FILE * f_kis_xml; /* output kismet netxml file */
	FILE * f_gps; /* output gps file      */
	FILE * f_cap; /* output cap file      */
	FILE * f_ivs; /* output ivs file      */
	FILE * f_xor; /* output prga file     */

	char * batt; /* Battery string       */
	int32_t channel[MAX_CARDS]; /* current channel #    */
	int32_t frequency[MAX_CARDS]; /* current frequency #    */
	int32_t ch_pipe[2]; /* current channel pipe */
	int32_t cd_pipe[2]; /* current card pipe    */
	int32_t gc_pipe[2]; /* gps coordinates pipe */
	float gps_loc[5]; /* gps coordinates      */
	int32_t save_gps; /* keep gps file flag   */
	int32_t usegpsd; /* do we use GPSd?      */
	int32_t * channels;
	//     int *frequencies;
	int32_t singlechan; /* channel hopping set 1*/
	int32_t singlefreq; /* frequency hopping: 1 */
	int32_t chswitch; /* switching method     */
	int32_t f_encrypt; /* encryption filter    */
	int32_t update_s; /* update delay in sec  */

	int32_t is_wlanng[MAX_CARDS]; /* set if wlan-ng       */
	int32_t is_orinoco[MAX_CARDS]; /* set if orinoco       */
	int32_t is_madwifing[MAX_CARDS]; /* set if madwifi-ng    */
	int32_t is_zd1211rw[MAX_CARDS]; /* set if zd1211rw    */
	volatile int do_exit; /* interrupt flag       */
	struct winsize ws; /* console window size  */

	char * elapsed_time; /* capture time			*/

	int32_t one_beacon; /* Record only 1 beacon?*/

	unsigned char sharedkey[3][4096]; /* array for 3 packets with a size of \
							   up to 4096Byte */
	time_t sk_start;
	char * prefix;
	int32_t sk_len;
	int32_t sk_len2;

	int32_t * own_channels; /* custom channel list  */
	int32_t * own_frequencies; /* custom frequency list  */

	int32_t record_data; /* do we record data?   */
	int32_t asso_client; /* only show associated clients */

	char * iwpriv;
	char * iwconfig;
	char * wlanctlng;
	char * wl;

	unsigned char wpa_bssid[6]; /* the wpa handshake bssid   */
	char message[512];
	char decloak;

	char is_berlin; /* is the switch --berlin set? */
	int32_t numaps; /* number of APs on the current list */
	int32_t maxnumaps; /* maximum nubers of APs on the list */
	int32_t maxaps; /* number of all APs found */
	int32_t berlin; /* number of seconds it takes in berlin to fill the whole screen
				   with APs*/
	/*
	 * The name for this option may look quite strange, here is the story behind
	 * it:
	 * During the CCC2007, 10 august 2007, we (hirte, Mister_X) went to visit
	 * Berlin
	 * and couldn't resist to turn on airodump-ng to see how much access point
	 * we can
	 * get during the trip from Finowfurt to Berlin. When we were in Berlin, the
	 * number
	 * of AP increase really fast, so fast that it couldn't fit in a screen,
	 * even rotated;
	 * the list was really huge (we have a picture of that). The 2 minutes
	 * timeout
	 * (if the last packet seen is higher than 2 minutes, the AP isn't shown
	 * anymore)
	 * wasn't enough, so we decided to create a new option to change that
	 * timeout.
	 * We implemented this option in the highest tower (TV Tower) of Berlin,
	 * eating an ice.
	 */

	int32_t show_ap;
	int32_t show_sta;
	int32_t show_ack;
	int32_t hide_known;

	int32_t hopfreq;

	char * s_file; /* source file to read packets */
	char * s_iface; /* source interface to read from */
	FILE * f_cap_in;
	struct pcap_file_header pfh_in;
	int32_t detect_anomaly; /* Detect WIPS protecting WEP in action */

	char * freqstring;
	int32_t freqoption;
	int32_t chanoption;
	int32_t active_scan_sim; /* simulates an active scan, sending probe requests */

	/* Airodump-ng start time: for kismet netxml file */
	char * airodump_start_time;

	int32_t output_format_pcap;
	int32_t output_format_csv;
	int32_t output_format_json;
	int32_t output_format_kismet_csv;
	int32_t output_format_kismet_netxml;
	pthread_t input_tid;
	int32_t sort_by;
	int32_t sort_inv;
	int32_t start_print_ap;
	int32_t start_print_sta;
	int32_t selected_ap;
	int32_t selected_sta;
	int32_t selection_ap;
	int32_t selection_sta;
	int32_t mark_cur_ap;
	int32_t num_cards;
	int32_t skip_columns;
	int32_t do_pause;
	int32_t do_sort_always;

	pthread_mutex_t mx_print; /* lock write access to ap LL   */
	pthread_mutex_t mx_sort; /* lock write access to ap LL   */

	unsigned char selected_bssid[6]; /* bssid that is selected */

	int32_t ignore_negative_one;
	u_int maxsize_essid_seen;
	int32_t show_manufacturer;
	int32_t show_uptime;
	int32_t file_write_interval;
	u_int maxsize_wps_seen;
        //struct tm gps_time; /* the timestamp from the gps data */
	int32_t show_wps;
#ifdef CONFIG_LIBNL
	int32_t htval;
#endif
	int32_t background_mode;
} G;
struct command_from_DSP{
	uint8_t mode;
	uint8_t db_board;
	uint32_t mboard;
	bool change_freq;
	bool change_gain;
	bool init_board;
	bool ntwrkscan;
	bool getgps;
	double freq;
	double gain;
	double samp_rate;
	double atten;
	double bandwidth;
	double lo_offset;
	double tx_power;
	char mboard_addr[34];
	char channel_list[14];
	char band[3];
	char technology[6];
	int32_t num_channels;
	char interface[50];
	char handshake[200];
	char offlinePcap[200];
};
#endif

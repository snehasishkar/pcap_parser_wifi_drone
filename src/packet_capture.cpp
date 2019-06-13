/*
 * pcaket_capture.cpp
 *
 *  Created on: 01-Apr-2019
 *      Author: saurabh raj
 */

#include <iostream>
#include <cstdlib>
#include <sys/types.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h> /* includes net/ethernet.h */
#include <net/ethernet.h>
#include <netinet/ip_icmp.h> //Provides declarations for icmp header
#include <netinet/udp.h>	//Provides declarations for udp header
#include <netinet/tcp.h>	//Provides declarations for tcp header
#include <netinet/ip.h>	//Provides declarations for ip header
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <stdbool.h>
#include <syslog.h>
#include <signal.h>
#include <math.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <errno.h>
#include <boost/thread.hpp>
#include <chrono>
#include <ctime>
#include <pwd.h>
#include <inttypes.h>
#include <sys/inotify.h>
#include <experimental/filesystem>
#include <cstring>
#include <map>

#include "../include/defs.h"
#include "../include/uniqueiv.h"
#include "../include/mcs_index_rates.h"
#include "../include/verifyssid.h"
#include "../include/vipl_printf.h"

#define NULL_MAC (unsigned char *) "\x00\x00\x00\x00\x00\x00"
#define BROADCAST (unsigned char *) "\xFF\xFF\xFF\xFF\xFF\xFF"
// BSSID const. length of 6 bytes; can be together with all the other types
#define IVS2_BSSID 0x0001
#define EVENT_SIZE  ( sizeof (struct inotify_event) )
#define EVENT_BUF_LEN     ( 1024 * ( EVENT_SIZE + 16 ) )
#define R_EARTH 6378
#define PI 3.1415926535897

using namespace std;

int32_t ivs_only=1;
const unsigned char ZERO[33] = {0x00};
pcap_t *descr_drone = NULL;
pcap_dumper_t *offline_dump = NULL;
char handshake_path[200] = {'\0'};
char oui_path[200] = {'\0'};
int32_t error_lvl = 0x00;
map<string, bool> discovered;

struct vipl_rf_tap{
	uint8_t channel;
	float gain;
	double sample_rate;
	double freq;
	double bandwidth;
	double latitude;
	double longitude;
	int32_t altitude;
	int32_t no_of_satellite;
};

static char * get_manufacturer_from_string(char * buffer)
{
	char * manuf = NULL;
	char * buffer_manuf;
	if (buffer != NULL && strlen(buffer) > 0)
	{
		buffer_manuf = strstr(buffer, "(hex)");
		if (buffer_manuf != NULL)
		{
			buffer_manuf += 6; // skip '(hex)' and one more character (there's
			// at least one 'space' character after that
			// string)
			while (*buffer_manuf == '\t' || *buffer_manuf == ' ')
			{
				++buffer_manuf;
			}

			// Did we stop at the manufacturer
			if (*buffer_manuf != '\0')
			{

				// First make sure there's no end of line
				if (buffer_manuf[strlen(buffer_manuf) - 1] == '\n'
					|| buffer_manuf[strlen(buffer_manuf) - 1] == '\r')
				{
					buffer_manuf[strlen(buffer_manuf) - 1] = '\0';
					if (*buffer_manuf != '\0'
						&& (buffer_manuf[strlen(buffer_manuf) - 1] == '\n'
							|| buffer[strlen(buffer_manuf) - 1] == '\r'))
					{
						buffer_manuf[strlen(buffer_manuf) - 1] = '\0';
					}
				}
				if (*buffer_manuf != '\0')
				{
					if ((manuf = (char *) malloc((strlen(buffer_manuf) + 1)
												 * sizeof(char)))
						== NULL)
					{
						perror("malloc failed");
						return NULL;
					}
					snprintf(
						manuf, strlen(buffer_manuf) + 1, "%s", buffer_manuf);
				}
			}
		}
	}

	return manuf;
}

#define OUI_STR_SIZE 8
#define MANUF_SIZE 128

char *get_manufacturer(unsigned char mac0, unsigned char mac1, unsigned char mac2){
	char oui[OUI_STR_SIZE + 1];
	char *manuf, *rmanuf;
	// char *buffer_manuf;
	char * manuf_str;
	struct oui * ptr;
	FILE * fp;
	char buffer[BUFSIZ];
	char temp[OUI_STR_SIZE + 1];
	unsigned char a[2];
	unsigned char b[2];
	unsigned char c[2];
	int32_t found = 0;

	if ((manuf = (char *) calloc(1, MANUF_SIZE * sizeof(char))) == NULL){
		vipl_printf("error: unable to assign memory for storing manufacturer", error_lvl, __FILE__, __LINE__);
		return NULL;
	}

	snprintf(oui, sizeof(oui), "%02X:%02X:%02X", mac0, mac1, mac2);
	if (G.manufList != NULL){
		// Search in the list
		ptr = G.manufList;
		while (ptr != NULL){
			found = !strncasecmp(ptr->id, oui, OUI_STR_SIZE);
			if (found){
				memcpy(manuf, ptr->manuf, MANUF_SIZE);
				break;
			}
			ptr = ptr->next;
		}
	}
	else{
		// If the file exist, then query it each time we need to get a
		// manufacturer.
		fp = fopen(oui_path, "r");
        if(fp==NULL){
        	vipl_printf("error: unable to find manufacturers list!!!", error_lvl, __FILE__, __LINE__);
        	return 0x00;
        }
		if(fp != NULL){
			memset(buffer, 0x00, sizeof(buffer));
			while (fgets(buffer, sizeof(buffer), fp) != NULL){
				if (strstr(buffer, "(hex)") == NULL){
					continue;
				}
				memset(a, 0x00, sizeof(a));
				memset(b, 0x00, sizeof(b));
				memset(c, 0x00, sizeof(c));
				if (sscanf(buffer, "%2c-%2c-%2c", a, b, c) == 3){
					snprintf(temp, sizeof(temp), "%c%c:%c%c:%c%c", a[0], a[1],b[0], b[1], c[0], c[1]);
					found = !memcmp(temp, oui, strlen(oui));
					if(found){
						manuf_str = get_manufacturer_from_string(buffer);
						if (manuf_str != NULL){
							snprintf(manuf, MANUF_SIZE, "%s", manuf_str);
							free(manuf_str);
						}
						break;
					}
				}
				memset(buffer, 0x00, sizeof(buffer));
			}
			fclose(fp);
		}
	}
	// Not found, use "Unknown".
	if (!found || *manuf == '\0'){
		memcpy(manuf, "Unknown", 7);
		manuf[strlen(manuf)] = '\0';
	}

	// Going in a smaller buffer
	rmanuf = (char *) realloc(manuf, (strlen(manuf) + 1) * sizeof(char));
	return (rmanuf) ? rmanuf : manuf;
}
#undef OUI_STR_SIZE
#undef MANUF_SIZE

void init(){
	G.manufList = NULL;
	discovered["DJI"] = false;
	discovered["skyrider"] = false;
	discovered["skyrider_night_hawk"] = false;
	discovered["360flight"] = false;
	discovered["3drsolo"] = false;
	discovered["propel_hd"] = false;
	discovered["xbm_720p"] = false;
	discovered["parrot_bebop"] = false;
	discovered["parrot_bebop2"] = false;
	discovered["parrot_adrone2"] = false;
	discovered["parrot_adrone"] = false;
}

struct drone_val{
	int16_t  roll;
	int16_t yaw;
	int16_t pitch;
	int16_t channel;
	double freq;
	double snr;
	double signal_strength;
	double curr_lat_drone;
	double curr_long_drone;
	double home_lat_drone;
	double home_long_drone;
	double alitutude;
	double height;
	uint8_t *drone_bssid;
	uint8_t *drone_essid;
	uint8_t *drone_uuid;
	uint8_t *drone_serial_no;
	char *drone_first_time_seen;
};

char json_filename[200]{0x00};

int32_t dump_write_json_drone_info(struct drone_val drone){
	 FILE *json = fopen(json_filename, "a+");
	 if(!json)
		 return 1;
	 fprintf(json, "{\"Manufacturer\":\"%s\", ", get_manufacturer(drone.drone_bssid[0],drone.drone_bssid[1],drone.drone_bssid[2]));
	 fprintf(json, "\"MAC-ID\":\"%02X:%02X:%02X:%02X:%02X:%02X\", ", drone.drone_bssid[0], drone.drone_bssid[1], drone.drone_bssid[2], drone.drone_bssid[3], drone.drone_bssid[4], drone.drone_bssid[5]);
     fprintf(json, "\"Model\":\"%s\", ", drone.drone_essid);
     char *oem = get_manufacturer(drone.drone_bssid[0], drone.drone_bssid[1], drone.drone_bssid[2]);
     if(discovered[oem] == false){
    	 time_t tinit = time(NULL);
    	 struct tm *ltime;
    	 ltime = localtime( &tinit);
    	 discovered[oem] = true;
         sprintf(drone.drone_first_time_seen, "%04d-%02d-%02dT%02d:%02d:%02d", 1900 + ltime->tm_year, 1 + ltime->tm_mon, ltime->tm_mday, ltime->tm_hour, ltime->tm_min,  ltime->tm_sec );
     }
     fprintf(json, "\"FirstTimeSeen\":\"%s\", ", drone.drone_first_time_seen);
     fprintf(json, "\"IsDrone\":\"true\", ");
     fprintf(json, "\"Channel\": %2d, \"snr\":%3d, ", drone.channel, drone.snr);
     fprintf(json, "\"Signal_strength\":%.3f}\n", drone.signal_strength);
     fclose(json);
     return 0;
}

int32_t dump_write_json_drone(struct drone_val drone){
	 FILE *json = fopen(json_filename, "a+");
	 if(!json)
		 return 1;
	 fprintf(json, "{\"Serial-No.\":\"%s\", ", drone.drone_serial_no);
	 fprintf(json, "\"UUID\":\"%s\", ", drone.drone_uuid);
	 fprintf(json, "\"Manufacturer\":\"%s\", ", get_manufacturer(drone.drone_bssid[0],drone.drone_bssid[1],drone.drone_bssid[2]));
	 fprintf(json, "\"MAC-ID\":\"%02X:%02X:%02X:%02X:%02X:%02X\", ", drone.drone_bssid[0], drone.drone_bssid[1], drone.drone_bssid[2], drone.drone_bssid[3], drone.drone_bssid[4], drone.drone_bssid[5]);
     fprintf(json, "\"Model\":\"%s\", ", drone.drone_essid);
     char *oem = get_manufacturer(drone.drone_bssid[0], drone.drone_bssid[1], drone.drone_bssid[2]);
     if(discovered[oem] == false){
      time_t tinit = time(NULL);
      struct tm *ltime;
      ltime = localtime( &tinit);
      discovered[oem] = true;
         sprintf(drone.drone_first_time_seen, "%04d-%02d-%02dT%02d:%02d:%02d", 1900 + ltime->tm_year, 1 + ltime->tm_mon, ltime->tm_mday, ltime->tm_hour, ltime->tm_min,  ltime->tm_sec );
     }
     fprintf(json, "\"FirstTimeSeen\":\"%s\", ", drone.drone_first_time_seen);
     fprintf(json, "\"IsDrone\":\"true\", ");
     fprintf(json, "\"Channel\": %2d, \"snr\":%3d, \"Signal_strength\":%f, ", drone.channel, drone.snr, drone.signal_strength);
     fprintf(json, "\"Current_Geo_location\":{\"lat\":%.6f, ", drone.curr_lat_drone);
     fprintf(json, "\"lon\":%.6f}, ", drone.curr_long_drone);
     fprintf(json, "\"ALTITUDE\":%.6f, ", drone.alitutude);
     fprintf(json, "\"Home_Geo_location\":{\"lat\":%.6f, ", drone.home_lat_drone);
     fprintf(json, "\"lon\":%.6f}, ", drone.home_long_drone);
     fprintf(json, "\"Height\": %.3f }\n", drone.height);
     fclose(json);
     return 0;
}

void packet_handler_drone(uint8_t *args, const struct pcap_pkthdr *pkh, const uint8_t *packet){
	struct radiotap_header{ // RadioTap is the standard for 802.11 reception/transmission/injection
			uint8_t it_rev; // Revision: Version of RadioTap
			uint8_t it_pad; // Padding: 0 - Aligns the fields onto natural word boundaries
			uint16_t it_len;// Length: 26 - entire length of RadioTap header
	};
	int32_t offset = 0;
	int32_t curr_counter = 0x00, max_counter = 0x00;
	struct drone_val droneValue;
	struct radiotap_header *rtaphdr = NULL;
	rtaphdr = (struct radiotap_header *) packet;
	offset = rtaphdr->it_len;
	pcap_dump((unsigned char*)offline_dump, pkh, packet);
	const u_char *h80211;
	h80211 = packet + offset;
	droneValue.drone_bssid = (uint8_t *)malloc(sizeof(uint8_t)*6);
	uint8_t *droneBSSID = (uint8_t *)malloc(sizeof(uint8_t)*6);
	bzero((char*)droneValue.drone_bssid, sizeof(uint8_t)*6);
	bzero((char*)droneBSSID, sizeof(uint8_t)*6);
	if(offset==18){
		if((packet[15]==1) && (packet[16]==0) && (packet[17]==0)){
			droneValue.signal_strength = packet[14] - 256;
			droneValue.snr = 0x00;
		}else{
			droneValue.signal_strength = packet[15] - 256;
		}
		droneValue.freq = (int32_t)packet[11]*256 + (int32_t)packet[10];
	}else if(offset==36){
		droneValue.signal_strength = packet[30] - 256;
		droneValue.freq = (int32_t)packet[27]*256 + (int32_t)packet[26];
	}
	int32_t caplen = pkh->caplen;
	int32_t seq = ((h80211[22] >> 4) + (h80211[23] << 4));
	switch (h80211[1] & 3){
	case 0:	memcpy(droneValue.drone_bssid, h80211 + 16, 6);
			break; // Adhoc
	case 1:	memcpy(droneValue.drone_bssid, h80211 + 4, 6);
			break; // ToDS
	case 2:	memcpy(droneValue.drone_bssid, h80211 + 10, 6);
			break; // FromDS
	case 3:	memcpy(droneValue.drone_bssid, h80211 + 10, 6);
			break; // WDS -> Transmitter taken as BSSID
	}
    unsigned char *p = (unsigned char*) h80211 + 36;
    while(p < h80211 + caplen){
    	if(p + 2 + p[1] > h80211 + caplen)
    		break;
    	if(p[0] == 0x03 || p[0] == 0x3d)
    		droneValue.channel = p[2];
    	p += 2 + p[1];
    }
    droneValue.drone_first_time_seen = (char *)malloc(sizeof(char)*50);
    bzero(droneValue.drone_first_time_seen, sizeof(char)*50);
	/*
	 * Get OEM of drone
	 */

	char *oem = get_manufacturer(droneValue.drone_bssid[0],droneValue.drone_bssid[1],droneValue.drone_bssid[2]);
	if(strcmp(oem,"DJI")==0x00){
		if(error_lvl==3){
			fprintf(stderr,"\n============================================\n");
			fprintf(stderr,"\t***DJI Drone detected on freq %fMHz, channel %d signal strength %f ***",droneValue.freq, droneValue.channel, droneValue.signal_strength);
		}

		/*
		 * Get ESSID of drone to obtain make and model
		 */
		int32_t count = (int32_t) (*(h80211+37));
		droneValue.drone_essid = (uint8_t *)malloc(sizeof(uint8_t)*33);
		bzero((char *)droneValue.drone_essid, sizeof(uint8_t)*33);
		memcpy(droneValue.drone_essid,(uint8_t *)h80211+38, count*sizeof(uint8_t));
		fprintf(stderr,"\n\t Model: %s",droneValue.drone_essid);

		/*
		 * For DJI Drones: check ie 221 and OUI should be 0x263712
		 */

		if(h80211[186+0x00]==0xdd){
			if((h80211[186+0x02]==0x26) && (h80211[186+0x03]==0x37) && (h80211[186+0x04]==0x12)){
				if((h80211[186+0x08]==0x10)){
					uint16_t state_info;
					memcpy(&state_info, h80211+186+13, sizeof(uint8_t)*2);
					droneValue.drone_serial_no = (uint8_t *)malloc(sizeof(uint8_t)*16);
					bzero((char *)droneValue.drone_serial_no, sizeof(uint8_t)*16);
					if((state_info&0x01)){
						memcpy(droneValue.drone_serial_no, (uint8_t *)h80211+186+15, sizeof(uint8_t)*16);
					}else{
						if(error_lvl==3)
							vipl_printf("error: invalid serial no", error_lvl, __FILE__, __LINE__);
					}
					if(state_info & 0x40){
						memcpy(&droneValue.curr_long_drone, (uint8_t *)h80211+186+31, sizeof(uint8_t)*4);
						memcpy(&droneValue.curr_lat_drone, (uint8_t *)h80211+186+35, sizeof(uint8_t)*4);
						droneValue.curr_long_drone = droneValue.curr_long_drone / 174533.0;
						droneValue.curr_lat_drone = droneValue.curr_lat_drone / 174533.0;
					}else{
						if(error_lvl)
							vipl_printf("error: no GPS fix", error_lvl, __FILE__, __LINE__);
					}
					if((state_info & 0x80)){
						memcpy(&droneValue.alitutude, (uint8_t *)h80211+186+39, sizeof(uint8_t)*2);
						//TODO: Check for little endianess
						droneValue.alitutude = htons(droneValue.alitutude);
					}else{
						if(error_lvl)
							vipl_printf("error: unable to get altitude", error_lvl, __FILE__, __LINE__);
						droneValue.alitutude = 0.00;
					}
					if(state_info & 0x100){
						memcpy(&droneValue.height, (uint8_t *)h80211+186+41, sizeof(uint8_t)*2);
						//TODO: Check for little endianess
						droneValue.height = htons(droneValue.height);
					}else{
						if(error_lvl)
							vipl_printf("error: unable to get height", error_lvl, __FILE__, __LINE__);
						droneValue.height = 0.00;
					}
					//TODO: To add velocity
					if((state_info & 0x400)||(state_info & 0x200)){

					}
					if(state_info & 0x04){
						memcpy(&droneValue.home_long_drone, (uint8_t *)h80211+186+54, sizeof(uint8_t)*4);
						memcpy(&droneValue.home_lat_drone, (uint8_t *)h80211+186+58, sizeof(uint8_t)*4);
						droneValue.home_long_drone = droneValue.home_long_drone/174533.0;
						droneValue.home_lat_drone = droneValue.home_lat_drone/174533.0;
					}
					if(state_info & 0x08){
						droneValue.drone_uuid = (uint8_t *)malloc(sizeof(uint8_t)*20);
						bzero((char *)droneValue.drone_uuid, sizeof(uint8_t)*20);
						int8_t uuid_len = h80211[186+63];
						memcpy(droneValue.drone_uuid, (uint8_t *)h80211+186+64, sizeof(uint8_t)*uuid_len);
					}
					if(error_lvl==3){
						fprintf(stderr,"\n\t Serial no: %s",droneValue.drone_serial_no);
						fprintf(stderr,"\n\t UUID no: %s",droneValue.drone_uuid);
						fprintf(stderr,"\n\t Current Lat: %6f Long %6f altitude %f height %f",droneValue.curr_lat_drone, droneValue.curr_long_drone, droneValue.alitutude, droneValue.height);
						fprintf(stderr,"\n\t Home Lat: %6f Long %6f altitude %f height %f",droneValue.home_lat_drone, droneValue.home_long_drone, droneValue.alitutude, droneValue.height);
						if(state_info & 0x20){
							fprintf(stderr,"\n\t Drone state on air");
						}
						if(state_info & 0x10)
							fprintf(stderr,"\n\t Drone motor on");
					}
					if(dump_write_json_drone( droneValue))
						vipl_printf("error: unable to write json", error_lvl, __FILE__, __LINE__);
				}else if((h80211[186+0x08]==0x11)){
					droneValue.drone_serial_no = (uint8_t *)malloc(sizeof(uint8_t)*16);
					bzero((char *)droneValue.drone_serial_no, sizeof(uint8_t)*16);
					memcpy(droneValue.drone_serial_no, (uint8_t *)h80211+186+10, sizeof(uint8_t)*16);
					droneValue.drone_uuid = (uint8_t *)malloc(sizeof(uint8_t)*10);
					bzero((char *)droneValue.drone_uuid, sizeof(uint8_t)*10);
					memcpy(droneValue.drone_uuid, (uint8_t *)h80211+186+10+16+1, sizeof(uint8_t)*10);
					if(error_lvl==3){
						fprintf(stderr,"\n\t Serial no: %s",droneValue.drone_serial_no);
						fprintf(stderr,"\n\t UUID no: %s",droneValue.drone_uuid);
					}
					if(dump_write_json_drone( droneValue))
						vipl_printf("error: unable to write json", error_lvl, __FILE__, __LINE__);
				}
			}
		}else{
			if(dump_write_json_drone_info( droneValue))
				vipl_printf("error: unable to write json", error_lvl, __FILE__, __LINE__);
		}
		if(error_lvl==3)
			fprintf(stderr,"\n============================================\n");
	}else if(strcmp(oem,"skyrider")==0x00){
		if(error_lvl==3){
			fprintf(stderr,"\n============================================\n");
			fprintf(stderr,"\t***Skyrider drone detected on freq %fMHz, channel %d signal strength %f ***",droneValue.freq, droneValue.channel, droneValue.signal_strength);
		}

		/*
		 * Get ESSID of drone to obtain make and model
		 */
		 int32_t count = (int32_t) (*(h80211+37));
		 droneValue.drone_essid = (uint8_t *)malloc(sizeof(uint8_t)*33);
		 bzero((char *)droneValue.drone_essid, sizeof(uint8_t)*33);
		 memcpy(droneValue.drone_essid,(uint8_t *)h80211+38, count*sizeof(uint8_t));
		 if(error_lvl==3)
			 fprintf(stderr,"\n\t Model: %s",droneValue.drone_essid);
		 if(error_lvl==3)
		 	 fprintf(stderr,"\n============================================\n");
	}else if(strcmp(oem,"skyrider_night_hawk")==0x00){
		if(error_lvl==3){
			fprintf(stderr,"\n============================================\n");
			fprintf(stderr,"\t***Skyrider Night Hawk drone detected on freq %fMHz, channel %d signal strength %f ***",droneValue.freq, droneValue.channel, droneValue.signal_strength);
		}

		/*
		 * Get ESSID of drone to obtain make and model
		 */
		 int32_t count = (int32_t) (*(h80211+37));
		 droneValue.drone_essid = (uint8_t *)malloc(sizeof(uint8_t)*33);
		 bzero((char *)droneValue.drone_essid, sizeof(uint8_t)*33);
		 memcpy(droneValue.drone_essid,(uint8_t *)h80211+38, count*sizeof(uint8_t));
		 if(error_lvl==3)
			 fprintf(stderr,"\n\t Model: %s",droneValue.drone_essid);
		 if(error_lvl==3)
		 	 fprintf(stderr,"\n============================================\n");
	}else if(strcmp(oem,"360flight")==0x00){
		if(error_lvl==3){
			fprintf(stderr,"\n============================================\n");
			fprintf(stderr,"\t***360flight drone detected on freq %fMHz, channel %d signal strength %f ***",droneValue.freq, droneValue.channel, droneValue.signal_strength);
		}

		/*
		 * Get ESSID of drone to obtain make and model
		 */
		 int32_t count = (int32_t) (*(h80211+37));
		 droneValue.drone_essid = (uint8_t *)malloc(sizeof(uint8_t)*33);
		 bzero((char *)droneValue.drone_essid, sizeof(uint8_t)*33);
		 memcpy(droneValue.drone_essid,(uint8_t *)h80211+38, count*sizeof(uint8_t));
		 if(error_lvl==3)
			 fprintf(stderr,"\n\t Model: %s",droneValue.drone_essid);
		 if(error_lvl==3)
		 	 fprintf(stderr,"\n============================================\n");
	}else if(strcmp(oem,"3drsolo")==0x00){
		if(error_lvl==3){
			fprintf(stderr,"\n============================================\n");
			fprintf(stderr,"\t***3drsolo drone detected on freq %fMHz, channel %d signal strength %f ***",droneValue.freq, droneValue.channel, droneValue.signal_strength);
		}

		/*
		 * Get ESSID of drone to obtain make and model
		 */
		 int32_t count = (int32_t) (*(h80211+37));
		 droneValue.drone_essid = (uint8_t *)malloc(sizeof(uint8_t)*33);
		 bzero((char *)droneValue.drone_essid, sizeof(uint8_t)*33);
		 memcpy(droneValue.drone_essid,(uint8_t *)h80211+38, count*sizeof(uint8_t));
		 if(error_lvl==3)
			 fprintf(stderr,"\n\t Model: %s",droneValue.drone_essid);
		 if(error_lvl==3)
		 	 fprintf(stderr,"\n============================================\n");
	}else if(strcmp(oem,"propel_hd")==0x00){
		if(error_lvl==3){
			fprintf(stderr,"\n============================================\n");
			fprintf(stderr,"\t***Propel_hd drone detected on freq %fMHz, channel %d signal strength %f ***",droneValue.freq, droneValue.channel, droneValue.signal_strength);
		}

		/*
		 * Get ESSID of drone to obtain make and model
		 */
		 int32_t count = (int32_t) (*(h80211+37));
		 droneValue.drone_essid = (uint8_t *)malloc(sizeof(uint8_t)*33);
		 bzero((char *)droneValue.drone_essid, sizeof(uint8_t)*33);
		 memcpy(droneValue.drone_essid,(uint8_t *)h80211+38, count*sizeof(uint8_t));
		 if(error_lvl==3)
			 fprintf(stderr,"\n\t Model: %s",droneValue.drone_essid);
		 if(error_lvl==3)
		 	 fprintf(stderr,"\n============================================\n");
	}else if(strcmp(oem,"xbm_720p")==0x00){
		if(error_lvl==3){
			fprintf(stderr,"\n============================================\n");
			fprintf(stderr,"\t***Xbm_720p drone detected on freq %fMHz, channel %d signal strength %f ***",droneValue.freq, droneValue.channel, droneValue.signal_strength);
		}

		/*
		 * Get ESSID of drone to obtain make and model
		 */
		 int32_t count = (int32_t) (*(h80211+37));
		 droneValue.drone_essid = (uint8_t *)malloc(sizeof(uint8_t)*33);
		 bzero((char *)droneValue.drone_essid, sizeof(uint8_t)*33);
		 memcpy(droneValue.drone_essid,(uint8_t *)h80211+38, count*sizeof(uint8_t));
		 if(error_lvl==3)
			 fprintf(stderr,"\n\t Model: %s",droneValue.drone_essid);
		 if(error_lvl==3)
		 	 fprintf(stderr,"\n============================================\n");
	}else if(strcmp(oem,"parrot_bebop")==0x00){
		if(error_lvl==3){
			fprintf(stderr,"\n============================================\n");
			fprintf(stderr,"\t***Parrot_bebop drone detected on freq %fMHz, channel %d signal strength %f ***",droneValue.freq, droneValue.channel, droneValue.signal_strength);
		}

		/*
		 * Get ESSID of drone to obtain make and model
		 */
		 int32_t count = (int32_t) (*(h80211+37));
		 droneValue.drone_essid = (uint8_t *)malloc(sizeof(uint8_t)*33);
		 bzero((char *)droneValue.drone_essid, sizeof(uint8_t)*33);
		 memcpy(droneValue.drone_essid,(uint8_t *)h80211+38, count*sizeof(uint8_t));
		 if(error_lvl==3)
			 fprintf(stderr,"\n\t Model: %s",droneValue.drone_essid);
		 if(error_lvl==3)
		 	 fprintf(stderr,"\n============================================\n");
	}else if(strcmp(oem,"parrot_bebop2")==0x00){
		if(error_lvl==3){
			fprintf(stderr,"\n============================================\n");
			fprintf(stderr,"\t***Parrot_bebop2 drone detected on freq %fMHz, channel %d signal strength %f ***",droneValue.freq, droneValue.channel, droneValue.signal_strength);
		}

		/*
		 * Get ESSID of drone to obtain make and model
		 */
		 int32_t count = (int32_t) (*(h80211+37));
		 droneValue.drone_essid = (uint8_t *)malloc(sizeof(uint8_t)*33);
		 bzero((char *)droneValue.drone_essid, sizeof(uint8_t)*33);
		 memcpy(droneValue.drone_essid,(uint8_t *)h80211+38, count*sizeof(uint8_t));
		 if(error_lvl==3)
			 fprintf(stderr,"\n\t Model: %s",droneValue.drone_essid);
		 if(error_lvl==3)
		 	 fprintf(stderr,"\n============================================\n");
	}else if(strcmp(oem,"parrot_adrone2")==0x00){
		if(error_lvl==3){
			fprintf(stderr,"\n============================================\n");
			fprintf(stderr,"\t***Parrot_adrone2 drone detected on freq %fMHz, channel %d signal strength %f ***",droneValue.freq, droneValue.channel, droneValue.signal_strength);
		}

		/*
		 * Get ESSID of drone to obtain make and model
		 */
		 int32_t count = (int32_t) (*(h80211+37));
		 droneValue.drone_essid = (uint8_t *)malloc(sizeof(uint8_t)*33);
		 bzero((char *)droneValue.drone_essid, sizeof(uint8_t)*33);
		 memcpy(droneValue.drone_essid,(uint8_t *)h80211+38, count*sizeof(uint8_t));
		 if(error_lvl==3)
			 fprintf(stderr,"\n\t Model: %s",droneValue.drone_essid);
		 if(error_lvl==3)
		 	 fprintf(stderr,"\n============================================\n");
	}else if(strcmp(oem,"parrot_adrone")==0x00){
		if(error_lvl==3){
			fprintf(stderr,"\n============================================\n");
			fprintf(stderr,"\t***Parrot_adrone drone detected on freq %fMHz, channel %d signal strength %f ***",droneValue.freq, droneValue.channel, droneValue.signal_strength);
		}

		/*
		 * Get ESSID of drone to obtain make and model
		 */
		 int32_t count = (int32_t) (*(h80211+37));
		 droneValue.drone_essid = (uint8_t *)malloc(sizeof(uint8_t)*33);
		 bzero((char *)droneValue.drone_essid, sizeof(uint8_t)*33);
		 memcpy(droneValue.drone_essid,(uint8_t *)h80211+38, count*sizeof(uint8_t));
		 if(error_lvl==3)
			 fprintf(stderr,"\n\t Model: %s",droneValue.drone_essid);
		 if(error_lvl==3)
		 	 fprintf(stderr,"\n============================================\n");
	}
}





#if 0
int32_t dump_write_json(char *json_filename){
    FILE *json = fopen(json_filename, "w");
    int32_t i, n, probes_written;
    struct tm *ltime;
    struct AP_info *ap_cur;
    struct ST_info *st_cur;
    char * temp;
    //append AP info
    time_t rawtime;
    struct tm * timeinfo;
    int32_t count = 0x00;
    ap_cur = G.ap_1st;
    time(&rawtime);
    timeinfo = localtime(&rawtime);
    while( ap_cur != NULL ){
    	if (time( NULL )-ap_cur->tlast > G.berlin){
    		ap_cur = ap_cur->next;
            continue;
        }

        if( memcmp( ap_cur->bssid, BROADCAST, 6 ) == 0 ){
            ap_cur = ap_cur->next;
            continue;
        }

        if(ap_cur->security != 0 && G.f_encrypt != 0 && ((ap_cur->security & G.f_encrypt) == 0)){
        	ap_cur = ap_cur->next;
            continue;
        }

        if(is_filtered_essid(ap_cur->essid)){
             ap_cur = ap_cur->next;
             continue;
        }
        struct timeval start;
        gettimeofday(&start,NULL);
        if(count==0x00){
        	 fprintf(json, "{\"BSSID\":\"%02X:%02X:%02X:%02X:%02X:%02X\", ", 	\
        	                            ap_cur->bssid[0], ap_cur->bssid[1],	\
        	                            ap_cur->bssid[2], ap_cur->bssid[3],	\
        	                            ap_cur->bssid[4], ap_cur->bssid[5] );
        	 count++;
        }
        else{
        	fprintf(json, "{\"BSSID\":\"%02X:%02X:%02X:%02X:%02X:%02X\", ", 	\
        	  	                       ap_cur->bssid[0], ap_cur->bssid[1],	\
        	  	                       ap_cur->bssid[2], ap_cur->bssid[3],	\
        	  	                       ap_cur->bssid[4], ap_cur->bssid[5] );
        }

	            ltime = localtime( &ap_cur->tinit );
	            fprintf( json, "\"FirstTimeSeen\":\"%04d-%02d-%02dT%02d:%02d:%02d\", ",	\
                        1900 + ltime->tm_year, 1 + ltime->tm_mon,	\
                        ltime->tm_mday, ltime->tm_hour,	\
                        ltime->tm_min,  ltime->tm_sec );

	            ltime = localtime( &ap_cur->tlast );
	            fprintf( json, "\"LastTimeSeen\":\"%04d-%02d-%02dT%02d:%02d:%02d\", ",	\
                        1900 + ltime->tm_year, 1 + ltime->tm_mon,	\
                        ltime->tm_mday, ltime->tm_hour,	\
                        ltime->tm_min,  ltime->tm_sec );
	            if(ap_cur->channel==-1)
	            	fprintf(json, "\"channel\":\"unknown\", ");
	            if(ap_cur->max_speed==-1)
	            	fprintf(json, "\"max_speed\":\"unknown\", ");
	            if(ap_cur->channel!=-1 && ap_cur->max_speed!=-1)
	            	fprintf( json, "\"channel\":%2d, \"max_speed\":%3d,",	\
                        ap_cur->channel,	\
                        ap_cur->max_speed );

                fprintf( json, "\"Privacy\":");

                if( (ap_cur->security & (STD_OPN|STD_WEP|STD_WPA|STD_WPA2)) == 0)
                	fprintf( json, "\"unknown\"" );
                else{
                        fprintf( json, "\"" );
                        if( ap_cur->security & STD_WPA2 ) fprintf( json, "WPA2" );
                        if( ap_cur->security & STD_WPA  ) fprintf( json, "WPA" );
                        if( ap_cur->security & STD_WEP  ) fprintf( json, "WEP" );
                        if( ap_cur->security & STD_OPN  ) fprintf( json, "OPN" );
                        fprintf( json, "\"" );
                }
                fprintf( json, ",");
                if( (ap_cur->security & (ENC_WEP|ENC_TKIP|ENC_WRAP|ENC_CCMP|ENC_WEP104|ENC_WEP40)) == 0 ){
                	if( ap_cur->security & STD_OPN )
                		fprintf( json, "\"Cipher\":\"\" ");
                	else
                		fprintf( json, "\"Cipher\":\"unknown\" ");
                }
                else{
                        fprintf( json, " \"Cipher\":\"" );
                        if( ap_cur->security & ENC_CCMP   ) fprintf( json, "CCMP ");
                        if( ap_cur->security & ENC_WRAP   ) fprintf( json, "WRAP ");
                        if( ap_cur->security & ENC_TKIP   ) fprintf( json, "TKIP ");
                        if( ap_cur->security & ENC_WEP104 ) fprintf( json, "WEP104 ");
                        if( ap_cur->security & ENC_WEP40  ) fprintf( json, "WEP40 ");
                        if( ap_cur->security & ENC_WEP    ) fprintf( json, "WEP ");
                       fprintf( json, "\"");
                }
                fprintf( json, ",");
                if( (ap_cur->security & (AUTH_OPN|AUTH_PSK|AUTH_MGT)) == 0 ){
                	if( ap_cur->security & STD_OPN )
                		fprintf( json, " \"Authentication\":\"\" ");
                	else
                		fprintf( json, " \"Authentication\":\"unknown\" ");
                }
                else{
                        if( ap_cur->security & AUTH_MGT   ) fprintf( json, " \"Authentication\":\"MGT\"");
                        if( ap_cur->security & AUTH_PSK   )
	                {
                                if( ap_cur->security & STD_WEP )
			                fprintf( json, "\"Authentication\":\"SKA\"");
			        else
		                        fprintf( json, "\"Authentication\":\"PSK\"");
		        }
                        if( ap_cur->security & AUTH_OPN   ) fprintf( json, " \"Authentication\":\"OPN\"");
                }

                fprintf( json, ", \"Signal_strength\":%3d, \"#beacons\":%8ld,\"#IV\":%8ld, ",
                        ap_cur->avg_power, \
                        ap_cur->nb_bcn,    \
                        ap_cur->nb_data );

                if(ap_cur->frequency==0)
                	ap_cur->distance=0;
                fprintf( json, "\"SNR\":%3d, \"Frequency\":%.3f, \"Distance\":%.6f, ", ap_cur->SNR, ap_cur->frequency, ap_cur->distance);

                fprintf( json, "\"GATEWAY\":\"%d.%d.%d.%d\", ",
                        ap_cur->lanip[0], ap_cur->lanip[1],  \
                        ap_cur->lanip[2], ap_cur->lanip[3] );

                fprintf( json, "\"ID-length\":%3d, ", ap_cur->ssid_length);

	        temp = format_text_for_csv(ap_cur->essid, ap_cur->ssid_length);
	        if(ap_cur->ssid_length==0)
	        	fprintf( json, "\"ESSID\":\"unknown\", ");
	        else
                fprintf( json, "\"ESSID\":\"%s\", ", ap_cur->essid );
	        free(temp);

                if(ap_cur->key != NULL)
                {
                        fprintf( json, "\"Key\":\"");
                        for(i=0; i<(int)strlen(ap_cur->key); i++)
                        {
                                fprintf( json, "%02X", ap_cur->key[i]);
                                if(i<(int)(strlen(ap_cur->key)-1))
                                        fprintf( json, ":");
                        }
                        fprintf(json, "\",");
                }

	            fprintf(json,"\"Manufacturer\":\"%s\", ",ap_cur->manuf);
                double lt,ln;
                double x, y;
                x = ((ap_cur->distance/1000)/R_EARTH) * (180.0/PI);
                lt = ap_cur->gps_loc_best[0] = rf_tap->latitude + x;
                ln = ap_cur->gps_loc_best[1] = rf_tap->longitude + (x/cos(lt * PI/180.0));
                ap_cur->gps_loc_max[0] = lt;
                ap_cur->gps_loc_max[1] = ln;
                ap_cur->gps_loc_best[2] = rf_tap->altitude;
                if(ap_cur->frequency==0)
                	lt=ln=0;
                if(lt || ln){
                fprintf( json, "\"ap_geo_location\":{\"lat\":%.6f, ",
                                        ap_cur->gps_loc_best[0] );


                fprintf( json, "\"lon\":%.6f}, ",
                                        ap_cur->gps_loc_best[1] );

                fprintf( json, "\"ALTITUDE\":%.6f, ",
                                        ap_cur->gps_loc_best[2] );
                fprintf( json, "\"geo_location_max\":{\"lat\":%.6f, ",
                                        ap_cur->gps_loc_max[0] );


                fprintf( json, "\"lon\":%.6f}, ",
                                        ap_cur->gps_loc_max[1] );

                }
                //terminate json AP data
                fprintf(json,"\"wlan_type\":\"AP\",\"timestamp\":\"%d\"}",(int)time(NULL));
	            fprintf(json, "\n");
                fflush( json);
                ap_cur = ap_cur->next;
        }

        //append STA info
       st_cur = G.st_1st;
        while( st_cur != NULL )
        {
                ap_cur = st_cur->base;

                if( ap_cur->nb_pkt < 2 )
                {
                        st_cur = st_cur->next;
                        continue;
                }

               if (time( NULL ) - st_cur->tlast > G.berlin )
                {
                        st_cur = st_cur->next;
                        continue;
               }

               struct timeval end;
               gettimeofday(&end,NULL);
               if(count == 0x00){
            	   fprintf( json, "{\"EquipmentMAC\":\"%02X:%02X:%02X:%02X:%02X:%02X\", ",st_cur->stmac[0], st_cur->stmac[1], \
            	               st_cur->stmac[2], st_cur->stmac[3],  \
            	               st_cur->stmac[4], st_cur->stmac[5] );
            	   count++;
               }
               else{
            	   fprintf( json, "{\"EquipmentMAC\":\"%02X:%02X:%02X:%02X:%02X:%02X\", ",st_cur->stmac[0], st_cur->stmac[1], \
            	               st_cur->stmac[2], st_cur->stmac[3],  \
            	               st_cur->stmac[4], st_cur->stmac[5] );
               }

                ltime = localtime( &st_cur->tinit );

                fprintf( json, "\"FirstTimeSeen\":\"%04d-%02d-%02dT%02d:%02d:%02d\", ",
                        1900 + ltime->tm_year, 1 + ltime->tm_mon,  \
                        ltime->tm_mday, ltime->tm_hour,   \
                        ltime->tm_min,  ltime->tm_sec );

                ltime = localtime( &st_cur->tlast );

               fprintf( json, "\"LastTimeSeen\":\"%04d-%02d-%02dT%02d:%02d:%02d\", ",
                        1900 + ltime->tm_year, 1 + ltime->tm_mon,  \
                        ltime->tm_mday, ltime->tm_hour,     \
                        ltime->tm_min,  ltime->tm_sec );

               fprintf( json, "\"Signal_strength\":%3d, \"#packets\":%8ld, ",
                        st_cur->power,    \
                        st_cur->nb_pkt );
               if(st_cur->frequency==0)
            	   st_cur->distance=0;
               fprintf( json, "\"SNR\":%3d, \"Frequency\":%.3f, \"Distance\":%.6f, ", st_cur->SNR, st_cur->frequency, st_cur->distance);

                if( ! memcmp( ap_cur->bssid, BROADCAST, 6 ) )
                        fprintf( json, "\"BSSID\":\"(not associated)\" ," );
                else
                        fprintf( json, "\"BSSID\":\"%02X:%02X:%02X:%02X:%02X:%02X\",",
                                ap_cur->bssid[0], ap_cur->bssid[1],  \
                                ap_cur->bssid[2], ap_cur->bssid[3],  \
                                ap_cur->bssid[4], ap_cur->bssid[5] );

                //add ESSID
                if(ap_cur->essid[0]==0)
                	fprintf(json,"\"ESSID\":\"unknown\", ");
                else
                	fprintf(json,"\"ESSID\":\"%s\", ",ap_cur->essid);


	        probes_written = 0;
                fprintf( json, "\"ProbedESSIDs\":\"");
                int pnum = 0;
                for( i = 0, n = 0; i < NB_PRB; i++ )
                {
                        if( st_cur->ssid_length[i] == 0 )
                                continue;

	                temp = format_text_for_csv((const unsigned char*) st_cur->probes[i], st_cur->ssid_length[i]);

	                if( probes_written == 0)
	                {
		                fprintf( json, "%s", temp);
		                probes_written = 1;
	                }
	                else
                {
		                fprintf( json, ",%s", temp);
	                }
                        pnum=pnum+1;
	                free(temp);
                }
                fprintf(json, "\",");
                //add number of probes
                fprintf(json, "\"#probes\":%d,",pnum);



                //add manufacturer for STA

	            fprintf(json,"\"Manufacturer\":\"%s\", ",st_cur->manuf);
                srand(time(NULL));
                double lt,ln;
                double x, y;
                x = ((st_cur->distance/1000)/R_EARTH) * (180.0/PI);
                lt = st_cur->gps_loc_best[0] = rf_tap->latitude + x;
                ln = st_cur->gps_loc_best[1] = rf_tap->longitude + (x/cos(lt * PI/180.0));
                st_cur->gps_loc_max[0] = lt;
                st_cur->gps_loc_max[1] = ln;
                st_cur->gps_loc_best[2] = rf_tap->altitude;
                if(st_cur->frequency==0)
                	lt=ln=0;
                if(lt || ln){
                fprintf( json, "\"equip_geo_location\":{\"lat\":%.6f, ",
                                                        st_cur->gps_loc_best[0] );


                fprintf( json, "\"lon\":%.6f}, ",
                                                      st_cur->gps_loc_best[1] );
                fprintf( json, "\"geo_location_max\":{\"lat\":%.6f, ",
                                        st_cur->gps_loc_max[0] );


                fprintf( json, "\"lon\":%.6f}, ",
                                        st_cur->gps_loc_max[1] );

                 }
                fprintf( json, "\"ALTITUDE\":%.6f, ",
                                                        st_cur->gps_loc_best[2] );

                //terminate json client data
                fprintf(json,"\"wlan_type\":\"CL\",\"timestamp\":\"%d\"}",(int)time(NULL));
                fprintf( json, "\n" );
                st_cur = st_cur->next;
        }
        fclose( json);

        return 1;
}
#endif

void init_json_parser(char *pcap_filename){
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	if(!(fp = pcap_open_offline(pcap_filename, errbuf))){
		char msg[200] = {0x00};
		sprintf(msg,"error: unable to opening pcap file for reading %s", pcap_filename);
		vipl_printf(msg, error_lvl, __FILE__, __LINE__);
		return ;
	}
	char filter[200]={0x00};
	struct bpf_program filter_to_apply;
	strcpy(filter, "type mgt subtype beacon");
	if(pcap_compile(fp, &filter_to_apply, filter, 0, 0) == -1)
	    vipl_printf("error: unable to create filter", error_lvl, __FILE__, __LINE__);
	if(pcap_setfilter(fp, &filter_to_apply) == -1)
		vipl_printf("error: unable to install filter",error_lvl,  __FILE__, __LINE__);
	int32_t rt = pcap_loop(fp, 0, packet_handler_drone, NULL);
	if(rt==-1)
		vipl_printf("error: parsing pcap files failed", error_lvl, __FILE__, __LINE__);
#if 0
	if(dump_write_json(json_filename))
		vipl_printf("info: json file written successfully\n", error_lvl, __FILE__, __LINE__);
#endif
	int32_t rtnval = remove(pcap_filename);
	if(rtnval!=0x00)
		vipl_printf("error: unable to delete pcap file after writing json", error_lvl, __FILE__, __LINE__);
}

int8_t parse_packets_drone(struct vipl_rf_tap *rf_tap_db, char *handshake, char *offlinePcap, char *oui,  int32_t error){
  clock_t start;
  int32_t fd, wd, i=0;
  char pcap_filename[200]{0x00}, dir_name[200]={0x00};
  char buffer_event[EVENT_BUF_LEN];
  int32_t length=0;
  error_lvl = error;
  init(); //initializes the global variables
  //rf_tap = rf_tap_db;
  strcpy(oui_path,oui);
  if(error_lvl==3)
	  vipl_printf("info: Drone detection thread started!!", error_lvl, __FILE__, __LINE__);
  const char *homedir;
  if((homedir = getenv("HOME"))==NULL)
	  homedir = getpwuid(getuid())->pw_dir;
  bzero(dir_name, 200);
  sprintf(dir_name, "%s/wpcap_temp", homedir);
  descr_drone = pcap_open_dead(DLT_IEEE802_11_RADIO, 65535 /* snaplen */);
#if 1
  offline_dump = pcap_dump_open(descr_drone, offlinePcap);
  if(offline_dump == NULL){
  		vipl_printf("error: in opening offline pcap file", error_lvl, __FILE__, __LINE__);
  }
  strcpy(handshake_path, handshake);
  //cout<<"handshake: "<<handshake<<"pcap: "<<offlinePcap<<endl;
#endif
  fd = inotify_init ();
  if(fd < 0)
      vipl_printf("error: in inotify_init", error_lvl, __FILE__, __LINE__);
  while(true){
      wd = inotify_add_watch(fd, dir_name, IN_MOVED_TO);
      length = read(fd, buffer_event, EVENT_BUF_LEN);
      if(length<0)
    	  vipl_printf("error: in read", error_lvl, __FILE__, __LINE__);
      i=0;
      while(i<length){
    	  struct inotify_event *event = (struct inotify_event *) &buffer_event[i];
    	  if(event->len){
    		  if(event->mask & IN_MOVED_TO){
    			  bzero(pcap_filename, 200);
    			  sprintf(pcap_filename, "%s/%s", dir_name, event->name);
    		  }
    	  }
    	  i += EVENT_SIZE + event->len;
      }
      bzero(json_filename, 200);
      start= clock();
      sprintf(json_filename, "/var/log/vehere/json/wifidump%lu.json", (unsigned long)start);
      init_json_parser(pcap_filename);

      pcap_close(descr_drone);
  }
  return 0;
}

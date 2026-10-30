#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>

#define LISTEN_IP "127.0.0.2"
#define LISTEN_PORT 53
#define BUF_SIZE 512

// سيرفرات الـ Upstream لتشغيل الداونلود بأقصى سرعة واستقرار
const char *UPSTREAM_SERVERS[] = {
    "1.1.1.1",   // Cloudflare
    "8.8.8.8",   // Google
    "77.88.8.8"  // Yandex
};
#define NUM_UPSTREAMS 3

// قائمة الحجب: تمنع تحديثات النظام، تحديثات الألعاب/التطبيقات، وتحديث اليوتيوب
const char *BLOCKLIST[] = {
    "playstation.net",
    "playstation.com",
    "playstation.org",
    "sonyentertainmentnetwork.com",
    "sony.com",
    "scea.com",
    "scee.com",
    "scei.co.jp",
    "youtube.com",
    "googlevideo.com",
    "ytimg.com",
    "youtu.be",
    "ggpht.com",
    NULL
};

// هيكل الإشعارات الخاص بالـ PS5
typedef struct {
    int type;
    int req_id;
    int priority;
    int msg_id;
    int target_id;
    int user_id;
    int unk1;
    int unk2;
    int app_id;
    int error_num;
    int unk3;
    char use_icon_image_uri;
    char message[1024];
    char icon_uri[1024];
    char unk[1024];
} OrbisNotificationRequest;

extern int sceKernelSendNotificationRequest(int device, OrbisNotificationRequest *req, size_t size, int blocking);

void send_ps5_notification(const char *text) {
    OrbisNotificationRequest req;
    memset(&req, 0, sizeof(req));
    req.target_id = -1;
    req.use_icon_image_uri = 1;
    snprintf(req.message, sizeof(req.message), "%s", text);
    snprintf(req.icon_uri, sizeof(req.icon_uri), "cxml://psnotification/tex_icon_system");
    sceKernelSendNotificationRequest(0, &req, sizeof(req), 0);
}

// دالة استخراج اسم الدومين من حزمة الـ DNS
void extract_domain(const unsigned char *buf, int len, char *domain, int max_len) {
    int i = 12; // تخطي الـ DNS Header (12 بايت)
    int pos = 0;
    while (i < len && buf[i] != 0) {
        int label_len = buf[i];
        if ((label_len & 0xC0) == 0xC0) break; // مؤشر ضغط
        i++;
        if (pos > 0 && pos < max_len - 1) {
            domain[pos++] = '.';
        }
        for (int j = 0; j < label_len && i < len && pos < max_len - 1; j++) {
            domain[pos++] = buf[i++];
        }
    }
    domain[pos] = '\0';
}

// فحص هل الدومين موجود في قائمة الحجب
int is_blocked(const char *domain) {
    for (int i = 0; BLOCKLIST[i] != NULL; i++) {
        if (strcasestr(domain, BLOCKLIST[i]) != NULL) {
            return 1;
        }
    }
    return 0;
}

int main() {
    int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if (sockfd < 0) return -1;

    int opt = 1;
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    struct sockaddr_in servaddr, cliaddr;
    memset(&servaddr, 0, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(LISTEN_PORT);
    servaddr.sin_addr.s_addr = inet_addr(LISTEN_IP);

    if (bind(sockfd, (const struct sockaddr *)&servaddr, sizeof(servaddr)) < 0) {
        send_ps5_notification("nanoDNS: Port 53 already in use!");
        close(sockfd);
        return -1;
    }

    send_ps5_notification("nanoDNS Active (127.0.0.2)\nSony & YouTube Updates Blocked!");

    unsigned char buf[BUF_SIZE];
    char domain[256];

    while (1) {
        socklen_t len = sizeof(cliaddr);
        int n = recvfrom(sockfd, buf, BUF_SIZE, 0, (struct sockaddr *)&cliaddr, &len);
        if (n <= 12) continue;

        extract_domain(buf, n, domain, sizeof(domain));

        if (is_blocked(domain)) {
            // الرد بـ NXDOMAIN (الدومين غير موجود) لقطع الاتصال فوراً عن سوني واليوتيوب
            buf[2] = 0x81; // QR=1 (Response), RD=1
            buf[3] = 0x83; // RA=1, RCODE=3 (NXDOMAIN)
            sendto(sockfd, buf, n, 0, (struct sockaddr *)&cliaddr, len);
        } else {
            // تمرير الطلب للإنترنت الخارجي عشان GLD Manager يشتغل
            int up_sock = socket(AF_INET, SOCK_DGRAM, 0);
            if (up_sock >= 0) {
                struct timeval tv;
                tv.tv_sec = 2; // مهلة ثانيتين لكل سيرفر
                tv.tv_usec = 0;
                setsockopt(up_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

                unsigned char reply[BUF_SIZE];
                int r = -1;

                for (int i = 0; i < NUM_UPSTREAMS; i++) {
                    struct sockaddr_in up_addr;
                    memset(&up_addr, 0, sizeof(up_addr));
                    up_addr.sin_family = AF_INET;
                    up_addr.sin_port = htons(53);
                    up_addr.sin_addr.s_addr = inet_addr(UPSTREAM_SERVERS[i]);

                    sendto(up_sock, buf, n, 0, (struct sockaddr *)&up_addr, sizeof(up_addr));
                    r = recvfrom(up_sock, reply, BUF_SIZE, 0, NULL, NULL);
                    if (r > 0) break; // لو السيرفر رد، نخرج من اللوب فوراً
                }

                if (r > 0) {
                    sendto(sockfd, reply, r, 0, (struct sockaddr *)&cliaddr, len);
                }
                close(up_sock);
            }
        }
    }

    close(sockfd);
    return 0;
}

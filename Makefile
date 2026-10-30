TARGET = nanoDNS.elf
SRCS = nanodns.c
OBJS = $(SRCS:.c=.o)

include $(PS5_PAYLOAD_SDK)/Makefile.inc

CFLAGS += -I$(PS5_PAYLOAD_SDK)/include -O2
LIBS += -lkernel -lc

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJS) $(LIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(TARGET) $(OBJS)

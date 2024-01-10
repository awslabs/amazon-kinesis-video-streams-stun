APP_NAME = "deserialzer"

# Source Files
SRCS += "deserializer.c"
SRCS += "../../lib/source/stun_deserializer.c"

# Include Directories
INCLUDE_DIRS += "-I../../lib/source/include/"

OBJS=$(SRCS:.c=.o)

CFLAGS+=-ggdb

.DEFAULT_GOAL:=build

build:
	$(CC) -o $(APP_NAME) $(SRCS) $(INCLUDE_DIRS) $(CFLAGS)

clean:
	rm -rf $(APP_NAME)

.PHONY: build clean

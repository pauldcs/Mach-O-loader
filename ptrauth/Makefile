NAME          := libptrauth.a
CC            := clang
SRCS_DIR      := .
OBJS_DIR      := .objs
BUILD_DIR     := build
INCS_DIR      := .

CFLAGS := \
	-fptrauth-intrinsics \
  -fptrauth-returns \
	-mmacosx-version-min=11.0

SRCS := \
	ptrauth.c

SRCS_OBJS := $(patsubst %.c,$(OBJS_DIR)/%.o,$(SRCS))

$(OBJS_DIR)/%.o:$(SRCS_DIR)/%.c
	@mkdir -vp $(dir $@)
	$(CC) \
		$(CFLAGS) \
		-MMD \
		-MP \
		-o $@ \
		-c $< \
		-I $(INCS_DIR)

all: $(NAME)

-include  $(SRCS_OBJS:.o=.d)

$(NAME): $(SRCS_OBJS)
	ar rc \
		$(NAME) \
		$(SRCS_OBJS)

clean:
	rm -rf $(OBJS_DIR)
	rm -rf .cache
	rm -rf .dSYM

fclean: clean
	rm -rf $(NAME)

re: fclean all

.PHONY	: all clean fclean re


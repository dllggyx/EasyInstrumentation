
CC = gcc
CFLAGS = -Wall -Wextra -g -O2

LDFLAGS = -ldl -lcapstone


# VICTIM_LDFLAGS = -no-pie
VICTIM_LDFLAGS = 


INSTR_SRCS = ptrace_injector.c utils.c instrument.c shared_mem.c
VICTIM_SRC = victim.c

INSTR_OBJS = $(INSTR_SRCS:.c=.o)
VICTIM_OBJ = $(VICTIM_SRC:.c=.o)

# --- Target Executables ---
INSTR_TARGET = instrument
VICTIM_TARGET = victim

# =============================================================================
#           Phony Targets
# =============================================================================


.PHONY: all
all: $(INSTR_TARGET) $(VICTIM_TARGET)

# Target to clean up all generated files
.PHONY: clean
clean:
	@echo "Cleaning up generated files..."
	rm -f $(INSTR_TARGET) $(VICTIM_TARGET) $(INSTR_OBJS) $(VICTIM_OBJ)

# Target to run the instrumentation (a convenience target)
.PHONY: run
run: all
	@echo "Running instrumentation on $(VICTIM_TARGET)..."
	./$(INSTR_TARGET) ./$(VICTIM_TARGET)

# =============================================================================
#           Build Rules
# =============================================================================

# --- Linking Rule for the 'instrument' Program ---
$(INSTR_TARGET): $(INSTR_OBJS)
	@echo "Linking $@..."
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)
	rm -f $(INSTR_OBJS)

# --- Linking Rule for the 'victim' Program ---

$(VICTIM_TARGET): $(VICTIM_OBJ)
	@echo "Linking $@ (non-PIE)..."
	$(CC) $(CFLAGS) -o $@ $^ $(VICTIM_LDFLAGS)
	rm -f $(VICTIM_OBJ)

# --- Generic Rule for Compiling .c to .o ---
%.o: %.c
	@echo "Compiling $< to $@..."
	$(CC) $(CFLAGS) -c -o $@ $<
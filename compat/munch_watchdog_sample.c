/* One observation of the SM8250 APSS watchdog during kernel startup. */
#include <arm/machine_routines.h>
#include <kern/misc_protos.h>
#include <kern/startup.h>
#include <pexpert/device_tree.h>
#include <string.h>

extern void loader_log_line(const char *line);

static bool
dt_property_matches(const char *path, const char *key, const void *expected,
    unsigned int expected_size)
{
	DTEntry entry;
	const void *value;
	unsigned int size;

	return SecureDTLookupEntry(NULL, path, &entry) == kSuccess &&
	       SecureDTGetProperty(entry, key, &value, &size) == kSuccess &&
	       size == expected_size && memcmp(value, expected, size) == 0;
}

__startup_func
static void
munch_watchdog_sample(void)
{
	const uint32_t readable = 1;
	char line[72];

	/* The munch loader sets this flag only after it has read WDT_EN itself. */
	if (!dt_property_matches("/arm-io", "device_type", "munch", sizeof("munch")) ||
	    !dt_property_matches("/chosen", "munch-wdt-readable", &readable, sizeof(readable))) {
		return;
	}

	/* Munch's live DT places the APSS watchdog at 0x17c10000.
	 * U-Boot's KPSS watchdog layout places the 32-bit WDT_EN register at +8. */
	unsigned int enable = ml_phys_read_word_64(0x17c10008ULL);
	snprintf(line, sizeof(line), "munch watchdog: kernel WDT_EN=0x%08x\n", enable);
	loader_log_line(line);
}
STARTUP(SYSCTL, STARTUP_RANK_MIDDLE, munch_watchdog_sample);

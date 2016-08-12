/*
 * This file is part of cc-oci-runtime.
 * 
 * Copyright (C) 2016 Intel Corporation
 * 
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 * 
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 * 
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <stdbool.h>
#include <stdlib.h>

#include <check.h>
#include <glib.h>

#include "../test_common.h"
#include "../../src/logging.h"

extern struct spec_handler mounts_spec_handler;

/*
* mounts json needs:
* - destination
* - type
* - source
* mounts json optional:
* - options
*/
static struct spec_handler_test tests[] = {
	{ TEST_DATA_DIR "/mounts-no-destination.json", false },
	{ TEST_DATA_DIR "/mounts-no-type.json",        false },
	{ TEST_DATA_DIR "/mounts-no-source.json",      false },
	{ TEST_DATA_DIR "/mounts-no-options.json",     true },
	{ TEST_DATA_DIR "/mounts.json",                true },
	{ NULL, false },
};

START_TEST(test_mounts_handle_section) {
	test_spec_handler(&mounts_spec_handler, tests);
} END_TEST

Suite* make_vm_suite(void) {
	Suite* s = suite_create(__FILE__);

	ADD_TEST(test_mounts_handle_section, s);

	return s;
}

int main(void) {
	int number_failed;
	Suite* s;
	SRunner* sr;
	struct cc_log_options options = { 0 };

	options.enable_debug = true;
	options.use_json = false;
	options.filename = g_strdup ("mounts_test_debug.log");
	(void)cc_oci_log_init(&options);

	s = make_vm_suite();
	sr = srunner_create(s);

	srunner_run_all(sr, CK_VERBOSE);
	number_failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	cc_oci_log_free (&options);

	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

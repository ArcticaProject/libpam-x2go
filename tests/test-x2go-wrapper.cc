/*
 * Copyright © 2012-2013 Mike Gabriel <mike.gabriel@das-netzwerkteam.de>.
 * Copyright © 2012 Canonical Ltd. All rights reserved.
 *
 * Author(s): Mike Gabriel <mike.gabriel@das-netzwerkteam.de>
 *            David Barth <david.barth@canonical.com>
 *
 */

#include <gtest/gtest.h>

extern "C" {

#include "mock_pam.h"
#include "mock_guest.h"
#include "pam-x2go-private.h"

	int x2goclient_wrapper (int argc, char * argv[]);

	const char * auth_check_path = AUTH_CHECK;

}

namespace {

  // The fixture for testing class Foo.
  class X2GoWrapperTest : public ::testing::Test {
  protected:
    // You can remove any or all of the following functions if its body
    // is empty.

    X2GoWrapperTest() {
      // You can do set-up work for each test here.
		setenv("HOME", "/tmp", 1 /* overwrite */);
    }

    virtual ~X2GoWrapperTest() {
      // You can do clean-up work that doesn't throw exceptions here.
    }

    // If the constructor and destructor are not enough for setting up
    // and cleaning up each test, you can define the following methods:

    virtual void SetUp() {
      // Code here will be called immediately after the constructor (right
      // before each test).
		unlink("/tmp/.x2go-socket");
    }

    virtual void TearDown() {
      // Code here will be called immediately after each test (right
      // before the destructor).
		unlink("/tmp/.x2go-socket");
    }

    // Objects declared here can be used by all tests in the test case for Foo.
  };

  TEST_F(X2GoWrapperTest, canLinkTheWholeGang) {
	  EXPECT_EQ (1, 1); // right, that's trivial, but that means
	                    // that I got all of the wrapper and pam to link there
  }

  TEST_F(X2GoWrapperTest, canCallPamOpenSession) {
	  const char *argv[] = { NULL };

	  pam_handle_t *pamh = pam_handle_new ();

	  EXPECT_EQ (PAM_SUCCESS,
				 pam_sm_authenticate (pamh, 0, 0, argv));
	  EXPECT_EQ (PAM_SUCCESS,
				 pam_sm_setcred (pamh, 0, 0, argv));

	  EXPECT_EQ (PAM_SUCCESS,
				 pam_sm_open_session (pamh, 0, 0, argv));
	  EXPECT_EQ(0, socket_sucker());
	  EXPECT_EQ (PAM_SUCCESS,
				 pam_sm_close_session (pamh, 0, 0, argv));
  }

}

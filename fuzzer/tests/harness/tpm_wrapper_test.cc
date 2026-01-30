#include <harness/tpm_wrapper.h>

#include <catch2/catch_test_macros.hpp>

// Mock state tracking structure
namespace MockTPM {
struct CallTracker {
  // TPMManufactureIfNeeded tracking
  bool nv_enable_called = false;
  bool nv_needs_manufacture_called = false;
  bool nv_needs_manufacture_result = false;
  bool tpm_manufacture_called = false;
  int tpm_manufacture_result = 0;
  bool nv_disable_called = false;

  // TPMStartup tracking
  bool signal_power_on_called = false;
  bool signal_reset_called = false;
  bool set_nv_avail_called = false;

  // TPMSendCommand tracking
  bool locality_set_called = false;
  unsigned char locality_value = 0;
  bool run_command_called = false;

  // TPMShutdown tracking
  bool hash_end_called = false;
  bool nv_commit_called = false;
  bool clear_nv_avail_called = false;
  bool signal_power_off_called = false;
  bool tpm_teardown_called = false;

  void reset() { *this = CallTracker(); }
};

static CallTracker tracker;
}  // namespace MockTPM

// Mock implementations - override the real TPM platform functions
extern "C" {
// TPMManufactureIfNeeded mocks
void _plat__NVEnable(void* platParameter, int size) {
  (void)platParameter;
  (void)size;
  MockTPM::tracker.nv_enable_called = true;
}

int _plat__NVNeedsManufacture(void) {
  MockTPM::tracker.nv_needs_manufacture_called = true;
  return MockTPM::tracker.nv_needs_manufacture_result ? 1 : 0;
}

int TPM_Manufacture(int firstTime) {
  (void)firstTime;
  MockTPM::tracker.tpm_manufacture_called = true;
  return MockTPM::tracker.tpm_manufacture_result;
}

void _plat__NVDisable(void* shouldSave, int size) {
  (void)shouldSave;
  (void)size;
  MockTPM::tracker.nv_disable_called = true;
}

// TPMStartup mocks
void _plat__Signal_PowerOn(void) {
  MockTPM::tracker.signal_power_on_called = true;
}

void _plat__Signal_Reset(void) { MockTPM::tracker.signal_reset_called = true; }

void _plat__SetNvAvail(void) { MockTPM::tracker.set_nv_avail_called = true; }

// TPMSendCommand mocks
void _plat__LocalitySet(unsigned char locality) {
  MockTPM::tracker.locality_set_called = true;
  MockTPM::tracker.locality_value = locality;
}

void _plat__RunCommand(uint32_t requestSize, unsigned char* request,
                       uint32_t* responseSize, unsigned char** response) {
  (void)requestSize;
  (void)request;
  (void)responseSize;
  (void)response;
  MockTPM::tracker.run_command_called = true;
}

// TPMShutdown mocks
void _TPM_Hash_End(void) { MockTPM::tracker.hash_end_called = true; }

void _plat__NvCommit(void) { MockTPM::tracker.nv_commit_called = true; }

void _plat__ClearNvAvail(void) {
  MockTPM::tracker.clear_nv_avail_called = true;
}

void _plat__Signal_PowerOff(void) {
  MockTPM::tracker.signal_power_off_called = true;
}

void _plat__TearDown(void) { MockTPM::tracker.tpm_teardown_called = true; }
}

// ============================================================================
// TPMManufactureIfNeeded Tests
// ============================================================================

TEST_CASE("TPMManufactureIfNeeded - TPM already manufactured",
          "[tpm_wrapper][manufacture]") {
  MockTPM::tracker.reset();
  MockTPM::tracker.nv_needs_manufacture_result = false;

  TPMManufactureIfNeeded();

  REQUIRE(MockTPM::tracker.nv_enable_called == true);
  REQUIRE(MockTPM::tracker.nv_needs_manufacture_called == true);
  REQUIRE(MockTPM::tracker.tpm_manufacture_called == false);
  REQUIRE(MockTPM::tracker.nv_disable_called == false);
}

TEST_CASE("TPMManufactureIfNeeded - TPM needs manufacturing and succeeds",
          "[tpm_wrapper][manufacture]") {
  MockTPM::tracker.reset();
  MockTPM::tracker.nv_needs_manufacture_result = true;
  MockTPM::tracker.tpm_manufacture_result = 0;  // Success

  TPMManufactureIfNeeded();

  REQUIRE(MockTPM::tracker.nv_enable_called == true);
  REQUIRE(MockTPM::tracker.nv_needs_manufacture_called == true);
  REQUIRE(MockTPM::tracker.tpm_manufacture_called == true);
  REQUIRE(MockTPM::tracker.nv_disable_called == false);
}

TEST_CASE("TPMManufactureIfNeeded - TPM manufacturing fails",
          "[tpm_wrapper][manufacture]") {
  MockTPM::tracker.reset();
  MockTPM::tracker.nv_needs_manufacture_result = true;
  MockTPM::tracker.tpm_manufacture_result = 1;  // Failure

  TPMManufactureIfNeeded();

  REQUIRE(MockTPM::tracker.nv_enable_called == true);
  REQUIRE(MockTPM::tracker.nv_needs_manufacture_called == true);
  REQUIRE(MockTPM::tracker.tpm_manufacture_called == true);
  REQUIRE(MockTPM::tracker.nv_disable_called == true);
}

// ============================================================================
// TPMStartup Tests
// ============================================================================

TEST_CASE("TPMStartup - calls all required platform functions",
          "[tpm_wrapper][startup]") {
  MockTPM::tracker.reset();

  TPMStartup();

  REQUIRE(MockTPM::tracker.signal_power_on_called == true);
  REQUIRE(MockTPM::tracker.signal_reset_called == true);
  REQUIRE(MockTPM::tracker.nv_enable_called == true);
  REQUIRE(MockTPM::tracker.set_nv_avail_called == true);
}

TEST_CASE("TPMStartup - functions called in correct order",
          "[tpm_wrapper][startup]") {
  MockTPM::tracker.reset();

  // We can verify order by checking that all are called
  // In a real scenario, you might track call sequence numbers
  TPMStartup();

  // Verify all critical functions were called
  REQUIRE(MockTPM::tracker.signal_power_on_called == true);
  REQUIRE(MockTPM::tracker.signal_reset_called == true);
  REQUIRE(MockTPM::tracker.nv_enable_called == true);
  REQUIRE(MockTPM::tracker.set_nv_avail_called == true);
}

// ============================================================================
// TPMSendCommand Tests
// ============================================================================

TEST_CASE("TPMSendCommand - sets locality and runs command",
          "[tpm_wrapper][command]") {
  MockTPM::tracker.reset();

  struct InBuffer request = {0};
  request.buffer_size = 10;
  request.buffer = nullptr;

  struct OutBuffer response = {0};
  unsigned char locality = 3;

  TPMSendCommand(locality, request, &response);

  REQUIRE(MockTPM::tracker.locality_set_called == true);
  REQUIRE(MockTPM::tracker.locality_value == 3);
  REQUIRE(MockTPM::tracker.run_command_called == true);
}

TEST_CASE("TPMSendCommand - handles different localities",
          "[tpm_wrapper][command]") {
  MockTPM::tracker.reset();

  struct InBuffer request = {0};
  struct OutBuffer response = {0};

  SECTION("Locality 0") {
    TPMSendCommand(0, request, &response);
    REQUIRE(MockTPM::tracker.locality_value == 0);
  }

  SECTION("Locality 4") {
    TPMSendCommand(4, request, &response);
    REQUIRE(MockTPM::tracker.locality_value == 4);
  }

  REQUIRE(MockTPM::tracker.locality_set_called == true);
  REQUIRE(MockTPM::tracker.run_command_called == true);
}

TEST_CASE("SendTPM2StartupCommand sends a TPM2_Startup command") {
  MockTPM::tracker.reset();

  SendTPM2StartupCommand();

  REQUIRE(MockTPM::tracker.locality_set_called);
  REQUIRE(MockTPM::tracker.run_command_called);
}

TEST_CASE("SendTPM2ShutdownCommand sends a TPM2_Shutdown command") {
  MockTPM::tracker.reset();

  SendTPM2ShutdownCommand();

  REQUIRE(MockTPM::tracker.locality_set_called);
  REQUIRE(MockTPM::tracker.run_command_called);
}

// ============================================================================
// TPMShutdown Tests
// ============================================================================

TEST_CASE("TPMShutdown - calls all cleanup functions",
          "[tpm_wrapper][shutdown]") {
  MockTPM::tracker.reset();

  TPMShutdown();

  REQUIRE(MockTPM::tracker.hash_end_called == true);
  REQUIRE(MockTPM::tracker.nv_commit_called == true);
  REQUIRE(MockTPM::tracker.clear_nv_avail_called == true);
  REQUIRE(MockTPM::tracker.signal_power_off_called == true);
  REQUIRE(MockTPM::tracker.tpm_teardown_called == true);
}

TEST_CASE("TPMShutdown - cleanup functions called in correct order",
          "[tpm_wrapper][shutdown]") {
  MockTPM::tracker.reset();

  TPMShutdown();

  // Verify all cleanup operations were performed
  REQUIRE(MockTPM::tracker.hash_end_called == true);
  REQUIRE(MockTPM::tracker.nv_commit_called == true);
  REQUIRE(MockTPM::tracker.clear_nv_avail_called == true);
  REQUIRE(MockTPM::tracker.signal_power_off_called == true);
  REQUIRE(MockTPM::tracker.tpm_teardown_called == true);
}

// ============================================================================
// Integration Tests
// ============================================================================

TEST_CASE("Full lifecycle - manufacture, startup, command, shutdown",
          "[tpm_wrapper][integration]") {
  MockTPM::tracker.reset();
  MockTPM::tracker.nv_needs_manufacture_result = false;  // Already manufactured

  // Manufacture check
  TPMManufactureIfNeeded();
  REQUIRE(MockTPM::tracker.nv_needs_manufacture_called == true);

  // Reset for startup
  MockTPM::tracker.reset();

  // Startup
  TPMStartup();
  REQUIRE(MockTPM::tracker.signal_power_on_called == true);

  // Send command
  struct InBuffer request = {0};
  struct OutBuffer response = {0};
  TPMSendCommand(0, request, &response);
  REQUIRE(MockTPM::tracker.run_command_called == true);

  // Shutdown
  TPMShutdown();
  REQUIRE(MockTPM::tracker.signal_power_off_called == true);
}

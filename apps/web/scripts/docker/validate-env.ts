import {
  assertAuthRuntimeConfiguration,
  assertAuthzedRuntimeConfiguration,
  warnOnAuthSecretRisks,
} from "../../lib/env";
import { assertSpringboardRuntimeConfiguration } from "../../modules/springboard/lib/runtime-config";

// Migrations reuse basic environment validation without client credentials.
// Only application startup opts into the stricter, configuration-only contract.
if (process.argv.includes("--server")) {
  assertAuthzedRuntimeConfiguration();
  assertAuthRuntimeConfiguration();
  warnOnAuthSecretRisks();
  assertSpringboardRuntimeConfiguration();
}

console.log("Environment variables validated successfully");

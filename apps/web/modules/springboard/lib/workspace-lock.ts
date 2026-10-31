import "server-only";
import type { Prisma } from "@formbricks/database/prisma";
import { OperationNotAllowedError } from "@formbricks/types/errors";
import { isSpringboardSingleWorkspace } from "./runtime-config";

/**
 * SPRINGBOARD_SINGLE_WORKSPACE=1: an organization keeps the one workspace it has. Only the creation of
 * a SECOND workspace is refused — an organization's first workspace (onboarding, setup) is untouched.
 *
 * This hides and blocks; it is not a limit. Upstream's licence-based workspace limit is a separate
 * check that this neither reads, changes nor replaces.
 */
export const SINGLE_WORKSPACE_ERROR_MESSAGE = "Creating additional workspaces is disabled on this instance.";

export const assertSpringboardWorkspaceCreationAllowed = async (
  tx: Pick<Prisma.TransactionClient, "workspace">,
  organizationId: string,
  isLocked: boolean = isSpringboardSingleWorkspace()
): Promise<void> => {
  if (!isLocked) return;
  const existing = await tx.workspace.count({ where: { organizationId } });
  if (existing > 0) {
    throw new OperationNotAllowedError(SINGLE_WORKSPACE_ERROR_MESSAGE);
  }
};

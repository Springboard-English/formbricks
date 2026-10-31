import { describe, expect, test, vi } from "vitest";
import { prisma } from "@formbricks/database";
import { OperationNotAllowedError } from "@formbricks/types/errors";
import { createWorkspace } from "@/modules/workspaces/settings/lib/workspace";

const tx = {
  workspace: { count: vi.fn(), create: vi.fn() },
  $queryRaw: vi.fn(),
};

vi.mock("@formbricks/database", () => ({ prisma: { $transaction: vi.fn() } }));
vi.mock("@/modules/springboard/lib/runtime-config", () => ({ isSpringboardSingleWorkspace: () => true }));

describe("createWorkspace with SPRINGBOARD_SINGLE_WORKSPACE=1", () => {
  test("refuses a second workspace before anything is written, whatever the licence limit says", async () => {
    tx.workspace.count.mockResolvedValue(1);
    vi.mocked(prisma.$transaction).mockImplementation((async (fn: (client: typeof tx) => unknown) =>
      fn(tx)) as never);

    await expect(
      createWorkspace("clxxxxxxxxxxxxxxxxxxxxxxx", { name: "Second" }, { workspaceLimit: Infinity })
    ).rejects.toBeInstanceOf(OperationNotAllowedError);
    expect(tx.workspace.create).not.toHaveBeenCalled();
  });
});

import { handleListUsers } from "@/modules/springboard/api/offboard-handlers";

export const dynamic = "force-dynamic";

export const GET = (request: Request): Promise<Response> => handleListUsers(request);

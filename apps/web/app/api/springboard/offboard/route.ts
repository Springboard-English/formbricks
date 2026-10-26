import { handleOffboard } from "@/modules/springboard/api/offboard-handlers";

export const dynamic = "force-dynamic";

export const POST = (request: Request): Promise<Response> => handleOffboard(request);

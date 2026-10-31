import { handleRespondentStart } from "@/modules/springboard/api/respondent-handlers";

export const dynamic = "force-dynamic";

export const GET = (request: Request): Promise<Response> => handleRespondentStart(request);

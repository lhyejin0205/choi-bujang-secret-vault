import { handleNotesRequest } from '../src/notes-handler.mjs';

export default function handler(request, response) {
  return handleNotesRequest(request, response);
}

import { writeAdminContent } from './admin-content.mjs';

export async function handler(event) {
  return writeAdminContent(event, 'save');
}

// 1. Text, not markup.
export function renderProfileCard(card: HTMLElement, user: { username: string; bio: string }) {
  const title = document.createElement("h2");
  title.textContent = user.username;
  card.replaceChildren(title);
}

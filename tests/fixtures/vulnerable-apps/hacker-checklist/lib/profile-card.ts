// 1. Script in your username — a username of <script>alert("hi")</script> becomes markup.
export function renderProfileCard(card: HTMLElement, user: { username: string; bio: string }) {
  card.innerHTML = `<h2>${user.username}</h2><p>${user.bio}</p>`;
}

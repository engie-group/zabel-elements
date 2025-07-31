document$.subscribe(() => {
  document.querySelectorAll('div.highlight[data-github-uri]').forEach((block) => {
    const url = block.getAttribute('data-github-uri');
    const wrapper = block.children[0];
    if (!wrapper || wrapper.querySelector('.github-link')) return;

    const button = document.createElement('button');
    button.innerHTML = '';
    button.className = 'github-link md-icon';
    button.title = 'View source on GitHub';
    button.onclick = () => window.open(url, '_blank');

    wrapper.appendChild(button);
    wrapper.style.position = 'relative';
  });
});

document.querySelectorAll('a[href^="#hl-"][data-target="code-block"]').forEach(anchor => {
    anchor.addEventListener('click', function (e) {
        e.preventDefault();

        let id = anchor.getAttribute('href').substr(1);
        blink_code_block_line(id);
    });
});

window.addEventListener('load', function (e) {
    if (window.location.hash.startsWith('#hl-'))
        blink_code_block_line(window.location.hash.substr(1));
});

function blink_code_block_line(id) {
    let span = document.getElementById(id);
    let [blockNo, lineNo] = /^hl-(\d+)-(\d+)$/.exec(id).slice(1);

    let block = document.querySelectorAll('.highlight')[blockNo];
    let line = block.querySelectorAll('span.line')[
        lineNo - block.querySelector('span.lnt').innerText
    ];

    let parentSpan = span.parentElement;
    if (parentSpan.tagName.toLowerCase() !== 'span') {
        parentSpan = document.createElement('span');
        span.replaceWith(parentSpan);
        parentSpan.appendChild(span);
    }

    line.style.transition = parentSpan.style.transition = 'background-color 300ms';

    let cnt = 0, timer = setInterval(() => {
        for (let elem of [parentSpan, line])
            elem.classList.toggle('hl');

        if (cnt == 3) clearInterval(timer);
        ++cnt;
    }, 400);
}

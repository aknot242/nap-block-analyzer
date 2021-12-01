const messages = document.querySelector('#messages');
const time = document.querySelector('#time');
const logCount = document.querySelector('#log-count');

let ws;
let showAlarms = false;

function clearMessages() {
    ws.send('clear');
}

function refreshMessages() {
    ws.send('refresh');
}

function showPolicy(data) {
    let displayedCount = 0
    jsonData = JSON.parse(data);
    messages.innerHTML = "";
    if (jsonData.messages !== undefined) {
        jsonData.messages.forEach(function (item) {
            if (showAlarms || (item.requestBlock || item.responseBlock)) {
                let tr = htmlToElement(`<tr><td>${item.supportId}</td><td class="center">${item.requestBlock ? makeColorText('red', '&#10060;') : makeColorText('green', '&#10004;')}</td><td class="center">${item.responseBlock ? makeColorText('red', '&#10060;') : makeColorText('green', '&#10004;')}</td><td>${item.requestMessages !== undefined && item.requestMessages.length > 0 ? `${item.requestMessages.join('<br>')}<br>&nbsp;<br>` : ''}${item.responseMessages !== undefined && item.responseMessages.length > 0 ? `${item.responseMessages.join('<br>')}` : ''}</td></tr>`);
                messages.appendChild(tr);
                displayedCount++
            }
        });
    }
    logCount.textContent = displayedCount;
    time.textContent = (new Date().toLocaleTimeString());
}

function toggleAlarms(checkbox) {
    checkbox.checked ? showAlarms = true : showAlarms = false;
    refreshMessages();
}

function makeColorText(color, text) {
    return `<span style="color: ${color};">${text}</span>`;
}

function htmlToElement(html) {
    let template = document.createElement('template');
    html = html.trim(); // Never return a text node of whitespace as the result
    template.innerHTML = html;
    return template.content.firstChild;
}

function toJsonString(json) {
    return JSON.stringify(json, null, 2)
}

function init() {
    if (ws) {
        ws.onerror = ws.onopen = ws.onclose = null;
        ws.close();
    }

    ws = new WebSocket('ws://localhost:6969');
    ws.onopen = () => {
        console.log('Connection opened!');
    }
    ws.onmessage = ({ data }) => {
        if (data !== undefined) showPolicy(data);
    }
    ws.onclose = function () {
        ws = null;
    }
}

init();

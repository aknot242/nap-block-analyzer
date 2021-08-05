const messages = document.querySelector('#messages');
const time = document.querySelector('#time');

let ws;

function clearMessages() {
    ws.send('clear');
}

function showPolicy(data) {
    jsonData = JSON.parse(data);
    messages.innerHTML = "";
    if (jsonData.messages !== undefined) {
        jsonData.messages.forEach(function (item) {
            let li = document.createElement('li');
            li.style.color = item.block ? "#600" : "#060";
            messages.appendChild(li);
            li.innerText = item.message;
        });
    }

    time.textContent = (new Date().toLocaleTimeString());
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
    ws.onmessage = ({ data }) => showPolicy(data);
    ws.onclose = function () {
        ws = null;
    }
}

init();

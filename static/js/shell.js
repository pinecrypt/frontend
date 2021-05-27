function onChooseFile(event) {
  if (!(window.File && window.FileReader && window.FileList && window.Blob)) {
    alert('The File APIs are not fully supported in this browser.');
  }

    var files = event.target.files;


      var reader = new FileReader();

      // Closure to capture the file information.
      reader.onload = (function(theFile) {
        return function(e) {
          // Render thumbnail.
          var span = document.createElement('span');
          span.innerHTML = ['<img class="thumb" src="', e.target.result,
                            '" title="', escape(theFile.name), '"/>'].join('');
          document.getElementById('list').insertBefore(span, null);
        };
      })(f);

      // Read in the image file as a data URL.
      reader.readAsDataURL(f);    
}

function init() {
    var url = "wss://" + window.location.hostname + "/pipe/" + window.location.hash.substring(1);
    console.info("Opening:", url);
    
    var term = new Terminal({rows: 50, cols: 200});
    term.open(document.getElementById('terminal'));
    term.write('Hello from \x1B[1;3;31mxterm.js\x1B[0m $ ')

    const ws = new WebSocket(url);

    // Connection opened
    ws.addEventListener('open', function (event) {
        console.log('Hello Server!');
    ws.send(JSON.stringify({"type": "session-start", "cols": 200, "rows": 50}));
    });

    // Listen for messages
    ws.addEventListener('message', function (event) {
        var e = JSON.parse(event.data);
        console.info(e);
        switch (e.type) {
          case "stdout":
            var buf = atob(e.value);
            term.write(buf.replace(/\n/g, '\n\r'));
            break
          case "exit":
            term.write("=== Process finished, no more input accepted ===");
            break;
        }
        
    });

    // Connection opened
    ws.addEventListener('close', function (event) {
        console.log('Bye Server!');
    });

    function runFakeTerminal() {
        if (term._initialized) {
            return;
        }

        term._initialized = true;

        term.prompt = () => {
            term.write('\r\n$ ');
        };

        term.writeln('Welcome to xterm.js');
        term.writeln('This is a local terminal emulation, without a real terminal in the back-end.');
        term.writeln('Type some keys and commands to play around.');
        term.writeln('');
        term.prompt();

        term.on('key', function(key, ev) {
            const printable = !ev.altKey && !ev.altGraphKey && !ev.ctrlKey && !ev.metaKey;

/*            if (ev.keyCode === 13) {
                term.prompt();
            } else if (ev.keyCode === 8) {
                // Do not delete the prompt
                if (term._core.buffer.x > 2) {
                    term.write('\b \b');
                }
            } else if (printable) {
//                term.write(key);
            }*/
            console.log("Got keypress:", key);
            if (key == "\r") key = "\n";
            ws.send(JSON.stringify({"type":"stdin", "value":btoa(key)}));
        });

        term.on('paste', function(data) {
            term.write(data);
        });
    }

    runFakeTerminal();
}

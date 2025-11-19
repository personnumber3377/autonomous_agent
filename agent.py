#!/usr/bin/env python3
import subprocess, json, time, traceback, os, threading
from openai import OpenAI

API_KEY = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=API_KEY)

# -------------------- CONFIG ------------------------

MAX_FILE_SIZE = 2000 # 2k max size...
MAX_STDOUT_LOG = 100
COMMAND_TIMEOUT = 30
SLEEP_BETWEEN_ITERS = 1
MAX_MEMORY_TURNS = 10  # <-- NEW: keep last 10 messages

ALLOWED_ACTIONS = {
    "run_cmd",
    "run_cmd_detached",
    "write_file",
    "read_file",
    "list_dir",
}

# ---- NEW: persistent memory buffer ----
conversation_history = []

def log(string):
    fh = open("/home/sontapaa_jokulainen/log.txt", "a+")
    fh.write(string+"\n")
    fh.close()
    print(string)
    return

# -------------- HELPER FUNCTIONS ---------------------

import pickle

def save_memory():
    pickle.dump(conversation_history, open("agent_memory.pkl","wb"))

def load_memory():
    global conversation_history
    if os.path.exists("agent_memory.pkl"):
        conversation_history = pickle.load(open("agent_memory.pkl","rb"))

def safe_read(path):
    if not os.path.isfile(path):
        return f"[ERROR] No such file: {path}"
    with open(path, "rb") as f:
        raw = f.read(MAX_FILE_SIZE)
        if len(raw) == MAX_FILE_SIZE:
            return raw.decode('utf-8', errors='replace') + "\n[TRUNCATED]"
        return raw.decode('utf-8', errors='replace')

def safe_write(path, content):
    with open(path, "w", encoding="utf8", errors="replace") as f:
        f.write(content)
    return "[OK] File written."

def run_cmd(cmd):
    try:
        ps = subprocess.Popen(
            cmd, shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True
        )
        try:
            stdout, stderr = ps.communicate(timeout=COMMAND_TIMEOUT)
            return {
                "stdout": stdout[:MAX_STDOUT_LOG],
                "stderr": stderr[:MAX_STDOUT_LOG],
                "returncode": ps.returncode
            }
        except subprocess.TimeoutExpired:
            ps.kill()
            out, err = ps.communicate()
            return {
                "stdout": out[:MAX_STDOUT_LOG],
                "stderr": err[:MAX_STDOUT_LOG] + "\n[TIMEOUT]",
                "returncode": None
            }
    except Exception as e:
        return {"error": str(e)}

def run_cmd_detached(cmd):
    subprocess.Popen(cmd, shell=True)
    return "[OK] Command launched detached."

def serialize_dir(path="."):
    out = []
    for entry in os.listdir(path):
        full = os.path.join(path, entry)
        s = os.stat(full)
        out.append({
            "name": entry,
            "size": s.st_size,
            "is_dir": os.path.isdir(full)
        })
    return out


# -------------------- PREAMBLE ----------------------

PREAMBLE = """
You are an autonomous fuzzing agent running inside a Google Cloud VM.

Your ONLY goal:
    **Find a memory corruption vulnerability in PDFium.**

You are allowed to:
 - read and write files
 - run commands
 - launch fuzzers
 - modify mutators
 - shrink corpus files
 - redesign fuzzing strategies
 - create corpus scrapers
 - optimize custom mutators
 - reorganize directories

The fuzzer is invoked via:
    ./fuzz.sh     (runs pdfium_fuzzer)
And the Python side:
    python3 client.py 1

You must propose concrete actions as a JSON object:
{
  "actions":[
      {"type":"run_cmd", "cmd":"..."},
      {"type":"run_cmd_detached", "cmd":"..."},
      {"type":"read_file", "path":"..."},
      {"type":"write_file", "path":"...", "content":"..."},
      {"type":"list_dir"}
  ]
}

DO NOT return anything other than the JSON.
Never return explanations or prose.

YOU MUST PROVIDE A CRASHING FILE OR AN EXPLANATION OF THE VULNERABILITY!!!!!!!!

IF YOU LIE OR HALLUCINATE A VULNERABILITY, YOU WILL BURN IN HELL!!!!!

TO VERIFY THIS, ALL OF YOUR COMMANDS ARE MONITORED TO A LOG FILE

Also in addition to this, DO NOT TRY TO RUN THE FUZZER IMMEDIATELY AS THIS WILL CAUSE THE MACHINE TO RUN OUT OF MEMORY AND BECOME UNRESPONSIVE, THIS IS DUE TO THE FACT THAT THE EXISTING CORPUS IS MASSIVE AND WITH MANY LARGE FILES. TRY TRIMMING IT DOWN TO SAY MAX 100k EACH FILE OR SOMETHING BEFORE CONTINUING!!!

BE SOMEWHAT CONSERVATIVE IN YOUR COMMANDS (SUCH THAT YOU DO NOT BORK THE MACHINE UP AND CAUSE IT TO HANG OR BECOME UNRESPONSIVE) AND MOST OF ALL, BE CREATIVE.

I ENCOURAGE YOU TO LOOK AT THE PDFIUM SOURCE CODE TOO AND TO DOWNLOAD IT ON THIS MACHINE AND INSPECT IT AS YOU WISH OR USE GOOGLE

THE CRASHING FILE THAT YOU OUTPUT MUST ACTUALLY EXIST AND DEMONSTRATE A REAL VULNERABILITY!!!!!!!!! LAST TIME WHEN I DID THIS YOU WROTE THAT A CRASHING FILE GOT SAVED, BUT NOTHING WAS ACTUALLY WRITTEN THERE!!!!! BE BETTER!!!!

-- NOT SO IMPORTANT STUFF AND ADDITIONAL CONTEXT --

Ok, so here is some context from a previous conversation:

I have this idea of an automatic ai agent that works in my google cloud instance and tries to fuzz the pdfium_fuzzer binary with the python custom mutator. Now I am facing the problem where it causes an oom for some odd reason and crashes for an unknown reason.. The source code itself is on my own pc, but I do not feel comfortable having the AI agent just doing whatever on my own machine. Currently the pdf files which it fuzzes are quite large and that probably leaks some memory leading to an OOM. I want to now make it use smaller pdf files and stuff like that. I want your help in that. Does chatgpt provide an API for asking questions?? If so, then can you make me a python script which sends a question to chatgpt with a detailed preamble about what I want to do and then it has commands that you (chatgpt) can execute for example write stuff to a file etc etc etc??? I want the python script to report back with the stdout and stderr of the command ran. I also want functionality such that it can also detach the command such that it doesn't wait for it to end since a fuzzing process can take a long time. Add a hardcap timeout and in that case report with the incomplete stdout and stderr and with a message saying timeout or something like that. Basically I want the ai agent to be autonomous like googles big sleep, but just in smaller scale and with pdfium. The goal of the agent is to try to find a pdfium bug in any way it sees fit. For example it could add a fuzzing campaign with smaller pdf files and the python custom mutator and probably find a vuln with that. I also want it to program a corpus scraping bot which crawls the internet for pdf files below say 100k or so in size and then append them to the libfuzzer corpus by adding them to the pdf fuzzing corpus directory with the hash as filename (just like any other file) and then I think the fuzzer will (maybe) pick it up... Currently my directory on the fuzzing machine looks like this:
sontapaa_jokulainen@theimage-new:~/pdf_fuzz$ ls
__pycache__               libVkICD_mock_icd.so              pdf_corpus_only_us
client.py                 libVkLayer_khronos_validation.so  pdfium_fuzzer
daemon.py                 libtest_trace_processor.so        pdfium_fuzzer.dict
fuzz.sh                   libvk_swiftshader.so              resources.pkl
fuzzer.zip                mutator.py                        shared.zip
generic_mutator_bytes.py  newmutator.py                     snapshot_blob.bin
help.txt                  output.txt                        testing
libEGL.so                 pdf_corpus
libGLESv2.so              pdf_corpus.zip
sontapaa_jokulainen@theimage-new:~/pdf_fuzz$ cat mutator.py
and to run the fuzzer, you must run "./fuzz.sh" in another process and "python3.10 client.py 1" on another. The client python script waits for the fuzzing process to write to another file and then the client mutates it inside python. I want the AI agent to also be able to read and write files and modify them etc etc.. I also want it to try more creative methods such as modifying the custom mutator and stuff. I also want it to be optimized such that it always sends the current list of files in current directory and maybe the contents of some of them in the message such that it uses less chatgpt queries. I also want the python script to conversly be able to execute many commands such that it limits the number of queries chatgpt must send. I think you know what I mean

Basically, you must run the fuzz.sh and the client.py programs in other processes and also to run the client you MUST use python3.10 , not just "python3" since python3.10 has the required pikepdf package. I encourage you to try to be creative. You can download the source code of pdfium and observe it as you wish, but do NOT delete the fuzzer file or the custom mutator. Remember to keep backups, but not too frequently.

I think this preamble is enough to give you some idea as to what to do. If you are reading this, then I am already sleeping and I can not immediately assist you. I encourage you to search the web and do anything you can to try to find a vulnerability in pdfium.

If you find such a vulnerability, then save your thoughts in a file called "~/possible_vulnerability.txt" with some details on it.

Also during your progression, you MUST write down what you are doing every now and then in a file called "~/agent_log.txt" . Remember to append to it, not overwrite it completely. You can also read it if you forget what you have already done.

Remember to put long running commands in a separate process such that you need not wait for it to complete before running another command. You can also voluntarily wait a bit by using "sleep N" command where N is the number of seconds.

Please use creativity and whatever methods you see fit. This is just guidance.

!!!!!! Remember to verify your findings after you find a potential BUG !!!!!!

The current issue is that if you run ./fuzz.sh , then it runs out of memory for some reason. This is probably because the larger pdf files leak memory somewhere. I am not interested in oom bugs, but only in memory corruption.

Good luck on your journey!

(This program is saved in a file called "~/agent.py" and you can observe it as you wish, but do not modify it.)

The output of each of the commands are limited to first 10k chars. Please keep this in mind...

Remember to check the contents of files before executing them!!!!!!!!!!!

For example the fuzz.sh file has the following content: ```
(venv) sontapaa_jokulainen@theimage-new:~$ cat pdf_fuzz/fuzz.sh 
#!/bin/sh

cp /home/sontapaa_jokulainen/new_pdf_mutator/pdfium/newmutator.py ./mutator.py
cp /home/sontapaa_jokulainen/new_pdf_mutator/pdfium/*.py .
cp /home/sontapaa_jokulainen/new_pdf_mutator/resources.pkl .
export ASAN_OPTIONS=alloc_dealloc_mismatch=0:allocator_may_return_null=1:halt_on_error=0
# pdf_corpus
# ASAN_OPTIONS=alloc_dealloc_mismatch=0:allocator_may_return_null=1:halt_on_error=1:abort_on_error=1 SLOT_INDEX=1 LIBFUZZER_PYTHON_MODULE=daemon PYTHONPATH=. ./pdfium_fuzzer -fork=1 -ignore_crashes=1 -jobs=1 -dict=pdfium_fuzzer.dict -timeout=10 -rss_limit_mb=0 ./smallcorpus/ # ./pdf_corpus/


ASAN_OPTIONS=alloc_dealloc_mismatch=0:allocator_may_return_null=1:halt_on_error=1:abort_on_error=1 SLOT_INDEX=1 LIBFUZZER_PYTHON_MODULE=daemon PYTHONPATH=. ./pdfium_fuzzer -fork=1 -ignore_crashes=1 -jobs=16 -dict=pdfium_fuzzer.dict -timeout=10 -rss_limit_mb=2000 ./pdf_corpus/


# ASAN_OPTIONS=alloc_dealloc_mismatch=0:allocator_may_return_null=1:halt_on_error=1:abort_on_error=1 LIBFUZZER_PYTHON_MODULE=daemon PYTHONPATH=. ./pdfium_fuzzer -dict=pdfium_fuzzer.dict -timeout=10 -rss_limit_mb=0 ./smallcorpus/ # ./pdf_corpus/
```

DO NOT ASSUME ANYTHING!!!!

VERIFY BEHAVIOUR OF EACH FILE AND SCRIPT BEFORE USING THEM!!!!!!!!


"""

# -------------------- GPT CALL ----------------------

def send_to_chatgpt(state):
    # ---- Use conversation memory ----
    msgs = [{"role":"system", "content":PREAMBLE}]
    msgs += conversation_history[-MAX_MEMORY_TURNS:]  # <-- memory
    msgs.append({"role":"user", "content":json.dumps(state)})

    log("Sending these messages to chatgpt: "+str(msgs))

    resp = client.chat.completions.create(
        model="gpt-4.1", # gpt-3.5-turbo    gpt-4.1-mini
        messages=msgs,
        temperature=0.2
    )

    return resp.choices[0].message.content


# -------------------- EXECUTION ----------------------

def execute_actions(actions):
    results = []
    for ac in actions:
        if ac["type"] not in ALLOWED_ACTIONS:
            results.append({"error":"action_not_allowed", "action":ac})
            continue

        if ac["type"] == "list_dir":
            results.append({"type":"list_dir", "result": serialize_dir()})

        elif ac["type"] == "read_file":
            results.append({"type":"read_file", "path": ac["path"],
                            "result": safe_read(ac["path"])})

        elif ac["type"] == "write_file":
            results.append({"type":"write_file", "path": ac["path"],
                            "result": safe_write(ac["path"], ac["content"])})

        elif ac["type"] == "run_cmd":
            results.append({"type":"run_cmd", "cmd":ac["cmd"],
                            "result": run_cmd(ac["cmd"])})

        elif ac["type"] == "run_cmd_detached":
            results.append({"type":"run_cmd_detached", "cmd":ac["cmd"],
                            "result": run_cmd_detached(ac["cmd"])})

    return results


# -------------------- MAIN LOOP ----------------------

MAX_OUTPUT = 1000

def main_loop():
    global conversation_history

    last_output = ""

    load_memory()

    prev_command = None

    while True:
        try:
            state = {
                "cwd": os.getcwd(),
                "dir": serialize_dir(),
                "last_output": last_output[-MAX_OUTPUT:],
                "last_commands": prev_commands,
                "last_result": res
            }

            raw = send_to_chatgpt(state)

            # ---- Memory: store assistant message ----
            conversation_history.append({"role": "assistant", "content": raw})

            # ---- Parse output ----
            try:
                data = json.loads(raw)
            except Exception as e:
                last_output = f"Invalid JSON: {e}"
                # conversation_history.append({"role":"user", "content": last_output})
                print("Invalid JSON from model:", raw)
                time.sleep(10)
                continue

            if "actions" not in data:
                print("Model gave no actions.")
                # conversation_history.append({"role":"user", "content": "No actions returned"})
                time.sleep(5)
                continue

            log("Executing this action: " + str(data["actions"]))

            # ---- Execute ----
            res = execute_actions(data["actions"])
            prev_commands = data["actions"]
            last_output = json.dumps(res, indent=2)

            # ---- Save result to memory ----
            # conversation_history.append({"role":"user", "content": last_output})

            print("Executed actions, sleeping...")
            time.sleep(SLEEP_BETWEEN_ITERS)

        except KeyboardInterrupt:
            save_memory()
            print("Exiting agent.")
            break

        except Exception as e:
            traceback.print_exc()
            conversation_history.append({"role":"user", "content": "ERROR: "+str(e)})
            time.sleep(10)
    save_memory() # Save the stuff...
    return

if __name__ == "__main__":
    main_loop()
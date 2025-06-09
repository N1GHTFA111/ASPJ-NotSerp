@app.route('/admin/dashboard/<path:username>', methods=['GET', 'POST'])
@login_required
@roles_required('SUPER_ADMIN')
def get_admin_dashboard(username):
    profile_pic_name = request.args.get('profile_pic_name')
    if username == flask_login.current_user.get_username():
        current_user = username
        print(current_user)
        logsmodel = LogsModel.query.all()
        logsmodel = sorted(logsmodel, key=lambda x: x.time)
        # Assuming you want to get the count of each distinct value in the "column_name" column
        result = db.session.query(LogsModel.classification, func.count(LogsModel.classification)).group_by(
            LogsModel.classification).all()

        priority_result = db.session.query(LogsModel.priority, func.count(LogsModel.priority)).group_by(
            LogsModel.priority).all()

        # date_results = db.session.query(LogsModel.time,
        #                                 func.count(LogsModel.time)).group_by(LogsModel.time).all()
        date_results = db.session.query(func.date(LogsModel.time),
                                        func.count(func.date(LogsModel.time))).group_by(func.date(LogsModel.time)).all()

        date_results = sorted(date_results, key=lambda x: x[0])
        print(date_results)
        # Store the results in a list of tuples
        count_list = [(value, count) for value, count in result]

        priority_list = [(value, count) for value, count in priority_result]

        date_list = [(value.strftime("%Y-%m-%d"), count) for value, count in date_results]

        logs_classification_list = []
        logs_count = []

        logs_priority_list = []
        logs_priority_count = []

        logs_date_list = []
        logs_date_count = []

        for count_tuple in count_list:
            logs_classification_list.append(count_tuple[0])
            logs_count.append(count_tuple[1])

        for count_tuple in priority_list:
            logs_priority_list.append(count_tuple[0])
            logs_priority_count.append(count_tuple[1])

        # i need a list of dates for the labels
        for tup in date_list:
            logs_date_list.append(tup[0])
            logs_date_count.append(tup[1])



        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Admin with user id of {flask_login.current_user.get_id()} accessed Security Logging System")

        filename_list = os.listdir("static/log_reports")

        createevirecform = AddToEvirec(request.form)

        page = request.args.get("page", 1, type=int)
        per_page = 10 # display 10 logs per page

        pagination_logs = LogsModel.query.order_by(LogsModel.time).paginate(page=page, per_page=per_page) # i want to paginate the logs model to 10 per page and order by time

        return render_template("dashboard_admin_ver2.html", profile_pic_name=profile_pic_name, username=username,
                               logs_classes=logs_classification_list, logs_count=logs_count,
                               logs_priority=logs_priority_list, logs_priority_count=logs_priority_count,
                               logs_model=logsmodel, log_files=filename_list,
                               logs_dates=logs_date_list, logs_date_count=logs_date_count, createevirec=createevirecform, logs_pages=pagination_logs)
    else:
        add_to_log(classification="JOB",
                   target_route=html.escape(request.url),
                   priority=2,
                   details=f"User with user id of {flask_login.current_user.get_id()} unauthorized access to Security Logging System")
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username()))
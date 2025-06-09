@app.route('/dashboard/<path:username>/profile', methods=['GET', 'POST'])
@login_required
@roles_required('USER')
def userProfile(username):
    profile_pic_name = request.args.get('profile_pic_name')
    # if flask_login.current_user.get_role() == "ADMIN":
    #     return redirect(url_for('get_admin_dashboard', username=flask_login.current_user.get_username()))
    # print(flask_login.current_user.get_first_name())
    updateuserform = UpdateUserForm(request.form)
    # if im updating
    if request.method == "POST" and updateuserform.validate():
        new_username = updateuserform.username.data
        new_email = updateuserform.email.data
        new_password = updateuserform.password.data
        new_password = new_password.encode('utf-8')
        mySalt = bcrypt.gensalt()
        pwd_hash = bcrypt.hashpw(new_password, mySalt)
        pwd_hash = pwd_hash.decode('utf-8')

        file = request.files["profile_pic"]
        print(file.filename)
        if len(request.files) != 0:
            extension = file.filename.split(".")[1]
            new_file_name = new_username + "." + extension
            file.save('static/profile_pics/' + new_file_name)

        current_user_to_update = UserModel.query.filter_by(email=flask_login.current_user.get_email()).first()
        # current_user_to_update.first_name = new_first_name
        # current_user_to_update.last_name = new_last_name
        # current_user_to_update.email = new_email
        # current_user_to_update.password = bcrypt_hash
        current_user_to_update.set_username(new_username)
        current_user_to_update.set_email(new_email)
        current_user_to_update.set_password(pwd_hash)

        if len(request.files) != 0:
            current_user_to_update.set_profile_pic(new_file_name)

        db.session.commit()
        login_user(current_user_to_update)
        return redirect(url_for('get_dashboard', username=current_user_to_update.get_username(),
                                logged_in=flask_login.current_user.is_authenticated, profile_pic_name=current_user_to_update.get_profile_pic()))
    else:
        if username == flask_login.current_user.get_username():
            current_user = username
            print(current_user)
            current_user_to_update = UserModel.query.filter_by(email=flask_login.current_user.email).first()
            updateuserform.username.data = current_user_to_update.get_username()
            updateuserform.email.data = current_user_to_update.get_email()


            return render_template("dashboard_user_profile.html", profile_pic_name=profile_pic_name, username=username, form=updateuserform)

        else:
            return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username(),
                                    profile_pic_name=flask_login.current_user.get_profile_pic()))


@app.route('/admin/dashboard/<path:username>/products', methods=['GET', 'POST'])
@login_required
@roles_required('PRODUCT_ADMIN')
def get_admin_product_dashboard(username):
    profile_pic_name = request.args.get('profile_pic_name')
    if username == flask_login.current_user.get_username():
        current_user = username
        print(current_user)
        print(profile_pic_name)

        all_products = InventoryModel.query.all()

        createproductform = CreateProductForm(request.form)
        updateproductform = UpdateProductForm(request.form)
        add_to_log(classification="Job",
                   target_route=html.escape(request.url),
                   priority=0,
                   details=f"Admin with user id of {flask_login.current_user.get_id()} accessed product dashboard.")

        return render_template("dashboard_admin_product.html", profile_pic_name=profile_pic_name,
                               username=username, all_products=all_products, updateform=updateproductform,
                               createform=createproductform)
    else:
        return redirect(url_for('get_dashboard', username=flask_login.current_user.get_username(),
                                profile_pic_name=flask_login.current_user.get_profile_pic()))

@app.route('/admin/dashboard/<path:username>/products/add_product', methods=['GET', 'POST'])
@login_required
@roles_required('PRODUCT_ADMIN')
def create_new_product(username):
    profile_pic_name = request.args.get('profile_pic_name')

    createproductform = CreateProductForm(request.form)

    if request.method == "POST":
        product_id = "PROD_" + secrets.token_urlsafe(32)
        product_name = createproductform.product_name.data
        product_description = createproductform.description.data
        product_quantity = createproductform.quantity.data
        unit_price = createproductform.unit_price.data

        file = request.files["product_pic"]
        if file.filename:
            extension = file.filename.split(".")[1]
            # new_file_name = secrets.randbits(32) + "." + extension
            new_file_name = Sentinel.generate_secure_filename(extension)
            file.save('static/product_pics/' + new_file_name)
        else:
            new_file_name = "default.jpg"

        create_product(
            product_id=product_id,
            product_name=product_name,
            description=product_description,
            quantity=product_quantity,
            unit_price=unit_price,
            product_pic=new_file_name
        )

        return redirect(url_for('get_admin_product_dashboard', profile_pic_name=profile_pic_name, username=username))

class CreateRoleForm(FlaskForm):
    rolename = StringField('Role Name', [validators.Length(min=1, max=200), validators.DataRequired()])
    havesuperadmin_permission = BooleanField('Super Admin Permission')
    havefinanceadmin_permission = BooleanField('Finance Admin Permission')
    haveproductadmin_permission = BooleanField('Product Admin Permission')
    haveblogadmin_permission = BooleanField('Blog Admin Permission')
    havepradmin_permission = BooleanField('PR Admin Permission')
    haveuser_permission = BooleanField('User Permission')

class UpdateRoleForm(FlaskForm):
    rolename = StringField('Role Name', [validators.Length(min=1, max=200), validators.DataRequired()])
    havesuperadmin_permission = BooleanField('Super Admin Permission')
    havefinanceadmin_permission = BooleanField('Finance Admin Permission')
    haveproductadmin_permission = BooleanField('Product Admin Permission')
    haveblogadmin_permission = BooleanField('Blog Admin Permission')
    havepradmin_permission = BooleanField('PR Admin Permission')
    haveuser_permission = BooleanField('User Permission')

@app.route('/admin/dashboard/<path:username>/products/update_product', methods=['GET', 'POST'])
@login_required
@roles_required('PRODUCT_ADMIN')
def update_product(username):
    # profile_pic_name = request.args.get('profile_pic_name')

    prod_id = request.args.get('product_id')

    createproductform = UpdateProductForm(request.form)

    if request.method == "POST":
        product_name = createproductform.product_name.data
        product_description = createproductform.description.data
        product_quantity = createproductform.quantity.data
        unit_price = createproductform.unit_price.data

        file = request.files["product_pic"]
        if file.filename:
            extension = file.filename.split(".")[1]
            new_file_name = Sentinel.generate_secure_filename(extension)
            file.save('static/product_pics/' + new_file_name)
        else:
            product_update = InventoryModel.query.filter_by(product_id=prod_id).first()
            new_file_name = product_update.get_product_pic()

        update_product_helper(
            product_id=prod_id,
            product_name=product_name,
            description=product_description,
            quantity=product_quantity,
            unit_price=unit_price,
            product_pic=new_file_name
        )

        return redirect(
            url_for('get_admin_product_dashboard', profile_pic_name=current_user.get_profile_pic(), username=username))

role_permission = db.session.execute(
                db.select(RoleModel).filter_by(rolename=current_user_role)).scalar_one()

@app.route('/admin/dashboard/<path:username>/products/delete_product', methods=['GET', 'POST'])
@login_required
@roles_required('PRODUCT_ADMIN')
def delete_product(username):
    product_id = request.args.get('product_id')

    if request.method == "POST":
        product_to_delete = InventoryModel.query.filter_by(product_id=product_id).first()
        if product_to_delete.get_product_pic() != 'default.jpg':
            os.remove('static/product_pics/' + product_to_delete.get_product_pic())

        delete_product_helper(prod_id=product_id)

        return redirect(
            url_for('get_admin_product_dashboard', profile_pic_name=current_user.get_profile_pic(), username=username))





var minTime = "{{ logs_model[0].get_time() }}"; // Assuming logs_model is a list of LogsModel objects
      var maxTime = "{{ logs_model[-1].get_time() }}"; // Assuming logs_model is a list of LogsModel objects
      var startTime = minTime;
      var endTime = maxTime;

      $(function() {
        $("#slider_time").slider({
          range: true,
          min: new Date(minTime).getTime(),
          max: new Date(maxTime).getTime(),
          step: 86400000, // One day in milliseconds
          values: [new Date(minTime).getTime(), new Date(maxTime).getTime()],
          slide: function(event, ui) {
            startTime = new Date(ui.values[0]).toISOString();
            endTime = new Date(ui.values[1]).toISOString();
            $("#timeFilter").val(startTime.slice(0, 10) + " - " + endTime.slice(0, 10));
            filterTableByTime();
          }
        });
        $("#timeFilter").val(minTime.slice(0, 10) + " - " + maxTime.slice(0, 10));
      });


    function filterTableByTime() {
        var input, table, tr, td, timeColumn, i, txtValue;
        input = document.getElementById("timeFilter");
        filter = input.value.toUpperCase();
        table = document.getElementById("logTable");
        tr = table.getElementsByTagName("tr");

        // Loop through all table rows, and hide those that don't match the filter
        for (i = 0; i < tr.length; i++) {
          timeColumn = tr[i].getElementsByTagName("td")[4]; // Assuming time is in the 5th column (index 4)
          if (timeColumn) {
            txtValue = timeColumn.textContent || timeColumn.innerText;
            var logTime = new Date(txtValue).toISOString();
            if (logTime >= startTime && logTime <= endTime) {
              tr[i].style.display = "";
            } else {
              tr[i].style.display = "none";
            }
          }
        }
      }

function
updateChartClass()
{
    var
logs_class = {{logs_classes | tojson}};
var
count = {{logs_count | tojson}};

var
classFilter = document.getElementById("classFilter").value;

var
filteredData = [];
for (var i=0; i < logs_class.length; i++)
{
if (logs_class[i].includes(classFilter))
{
    filteredData.push(count[i]);
} else {
    filteredData.push(0);
}
}


var
chartcanvas = document.getElementById("chartjs-doughnut");
var
chart = Chart.getChart(chartcanvas);
chart.data.datasets[0].data = filteredData;
chart.update();
}




<!-- Pagination controls -->
<!--                    <div class="pagination">-->
<!--                        {% if logs_pages.has_prev %}-->
<!--                        <a class="page-link" href="{{ url_for('get_admin_dashboard', username=current_user.get_username(), profile_pic_name=current_user.get_profile_pic(), page=logs_pages.prev_num) }}">Previous</a>-->
<!--                        {% else %}-->
<!--                        <span class="page-link disabled">Previous</span>-->
<!--                        {% endif %}-->

<!--                        {% for page in logs_pages.iter_pages() %}-->
<!--                        {% if page %}-->
<!--                        {% if logs_pages.page == page %}-->
<!--                        <span class="page-link current-page">{{ page }}</span>-->
<!--                        {% else %}-->
<!--                        <a class="page-link" href="{{ url_for('get_admin_dashboard', username=current_user.get_username(), profile_pic_name=current_user.get_profile_pic(), page=page) }}">{{ page }}</a>-->
<!--                        {% endif %}-->
<!--                        {% else %}-->
<!--                        <span class="ellipsis">...</span>-->
<!--                        {% endif %}-->
<!--                        {% endfor %}-->

<!--                        {% if logs_pages.has_next %}-->
<!--                        <a class="page-link" href="{{ url_for('get_admin_dashboard', username=current_user.get_username(), profile_pic_name=current_user.get_profile_pic(), page=logs_pages.next_num) }}">Next</a>-->
<!--                        {% else %}-->
<!--                        <span class="page-link disabled">Next</span>-->
<!--                        {% endif %}-->
<!--                    </div>-->





<td>
                                                                <form action="{{ url_for('delete_evirec_item', username=current_user.get_username(), logged_in=current_user.is_authenticated, profile_pic_name=current_user.get_profile_pic() , evirec_id=evirec_entry.get_evirec_id()) }}"
                                                                      method="POST">
                                                                    <input type="hidden" name="csrf_token"
                                                                           value="{{ csrf_token() }}">
                                                                    <!--                    <input type="submit" value="Delete" class="btn btn-danger">-->
                                                                    <button type="button" class="btn btn-danger"
                                                                            data-bs-toggle="modal"
                                                                            data-bs-target="#myModal_{{evirec_entry.get_evirec_id()}}_deleteEvirecItem"
                                                                            >
                                                                        Delete
                                                                    </button>
                                                                                        Modal
                                                                    <div class="modal fade"
                                                                         id="myModal_{{evirec_entry.get_evirec_id()}}_deleteEvirecItem"
                                                                         aria-hidden="true"
                                                                    style="z-index: 2;">
                                                                        <div class="modal-dialog">
                                                                            <div class="modal-content">

                                                                                <!--                                Modal Header-->
                                                                                <div class="modal-header">
                                                                                    <h4 class="modal-title">Delete
                                                                                        Confirmation</h4>
                                                                                    <button type="button"
                                                                                            class="btn-close"
                                                                                            data-bs-dismiss="modal"></button>
                                                                                </div>

                                                                                <!--                                Modal Body-->
                                                                                <div class="modal-body">
                                                                                    Are you sure you want to delete this
                                                                                    user?
                                                                                </div>

                                                                                <!--                                Modal Footer-->
                                                                                <div class="modal-footer">
                                                                                    <input type="submit" value="Delete"
                                                                                           class="btn btn-danger">
                                                                                    <button type="button"
                                                                                            class="btn btn-secondary"
                                                                                            data-bs-dismiss="modal">
                                                                                        Cancel
                                                                                    </button>
                                                                                </div>

                                                                            </div>
                                                                        </div>
                                                                    </div>
                                                                </form>
                                                            </td>



file = request.files["profile_pic"]
main_file = file
        file_to_test = file.stream
        file_name = file.filename
        if file.filename:

            # MARKER FOR FILE UPLOAD PROTECTION
            # use sentinel to check for filename, content and extension, file signature as well
            if Sentinel.FileChecker.is_file_safe(file_to_test, file_name):

                # reset buffer position before save
                main_file.seek(0)

                # prevents double extension vulnerability and command injection via file name
                extension = file.filename.split(".")[1]
                new_file_name = username + "." + extension
                file.save('static/profile_pics/' + new_file_name)
                # with open('static/profile_pics/' + new_file_name, 'wb') as f:
                #     f.write(file_buffer.read())
            else:
                add_to_log("SUSPICIOUS FILE UPLOAD", request.url, 2, f"Suspicious File rejected: {file.filename}")
                new_file_name = "default.jpg"
        else:
            new_file_name = "default.jpg"

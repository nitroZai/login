from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode
from email import message
from django.shortcuts import render, redirect
# To store the sign up data to Users part in Data base we use the below library
from django.contrib.auth.models import User
# messages library
from django.contrib import messages
# The below library helps us to check whether username and password are valid or not
from django.contrib.auth import authenticate
# The below library helps us to login
from django.contrib.auth import login
# The below library helps us to logout
from django.contrib.auth import logout
from school import settings
# The below library is used to send mails
from django.core.mail import send_mail
# The below gives us the function get_current_site, helps us to get the current site address
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string
from django.utils.encoding import force_bytes, force_str
from authentication.tokens import *
from django.core.mail import EmailMessage
def home(request):

    context = {}

    return render(request, 'home.html', context)


def signup(request):

    if request.method == "POST":
        username = request.POST.get('username')
        fname = request.POST.get('fname')
        lname = request.POST.get('lname')
        email = request.POST.get('email')
        pass1 = request.POST.get('pass2')
        pass2 = request.POST.get('pass2')

        if User.objects.filter(username = username):
            messages.error(request, "Username already exist!")
            return redirect('home')
        
        if User.objects.filter(email = email):
            messages.error(request, "Email already exist!")
            return redirect('home')

        if len(username) < 2:
            messages.error(request, "Username is too short")

        if pass1 != pass2:
            messages.error(request, "Your passwords do not match")

        if not username.isalnum():
            messages.error(request, "Username must be alpha numeric")
            return redirect('home')


        newUser = User.objects.create_user(
            username, email, pass1 
        )
        newUser.first_name = fname
        newUser.last_name = lname
        
        # Ensures the User isn't getting his login rights yet, until the confirmation via mail is done
        newUser.is_active = False
        newUser.save()

        messages.success(request, "Your account is successfully created")
        
        subject = "Welcome to Django Hero"
        message = "Hello" + newUser.first_name + "! \n" + "Congratulations on taking the first towards being a django hero" + "\n\n You're one step away from being part of our family, Check another mail to confirm!"
        from_email = settings.EMAIL_HOST_USER
        to_list = [newUser.email]
        send_mail(subject,message,from_email, to_list,fail_silently=True)


        # Confirmation Email Part
        current_site = get_current_site(request)
        email_subject = "Email Confirmation | Django Hero"
        message2 = render_to_string('email_confirmation.html', {'name':newUser.first_name, 
        'domain': current_site, 
        'uid': urlsafe_base64_encode(force_bytes(newUser.pk)),
        'token': generate_token.make_token(newUser), }
        )
        emailObject = EmailMessage(
            email_subject,
            message2,
            settings.EMAIL_HOST_USER,
            [newUser.email],
        )
        emailObject.fail_silently = True
        emailObject.send()

        return redirect('signin')
        
    context = {}

    return render(request, 'authentication/signup.html', context)


def signin(request):
    if request.method == "POST":
        username = request.POST['username']
        pass1 = request.POST['pass1']

        user = authenticate(username=username, password=pass1)

        if user is not None:
            login(request,user)
            fname = user.first_name 
            return render(request, 'home.html', {'fname': fname})
        else: 
            messages.error(request, "Wrong Credentials")
            return redirect('home')

    return render(request, 'authentication/signin.html')


def signout(request):
    logout(request)
    messages.success(request, "You are successfully logged out")    
    return redirect('home')


def activate(request, uid64, token):
    try:
        uid = force_str(urlsafe_base64_decode(uid64))
        # Decodes the tokens

        newUser = User.objects.get(pk=uid)
    except (TypeError, ValueError, OverflowError, User.DoesNotExist):
        newUser = None

    if newUser is not None and generate_token.check_token(newUser, token):
        newUser.is_active = True
        newUser.save()
        login(request, newUser)
        return redirect('home')
    else:
        return render(request, 'conf_fail.html')
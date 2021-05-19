from django.shortcuts import render,HttpResponse,redirect
from django.contrib import messages
from django.contrib.auth import authenticate,login,logout
from django.contrib.auth.models import User
from .models import *
import uuid
from django.conf import settings
from django.core.mail import send_mail
from .helpers import send_forget_password_mail


def ecom(request):
    return render(request,'LS.html')

def handlesignup(request):
    #get the parameters
    if request.method == 'POST':
        username = request.POST['username']
        email = request.POST['email']
        phone = request.POST['phone']
        password = request.POST['password']

        #check for error input
        if User.objects.filter(username=username).first():
            messages.success(request, 'Username is taken.')
            return redirect('ecom')

        if User.objects.filter(email=email).first():
            messages.success(request, 'Account already exist with this email')
            return redirect('ecom')

        if (len(phone) < 10) or (len(phone) > 10):
            messages.error(request,'Please Enter 10 Digit Phone Number')
            return redirect('ecom')
        elif len(password) < 8:
            messages.error(request, 'Password is too short')
            return redirect('ecom')
        else:
            #create the user
            myuser = User.objects.create_user(username, email, password)
            myuser.Phoneno = phone
            myuser.save()
            auth_token = str(uuid.uuid4())
            profile_obj = Profile.objects.create(user=myuser, auth_token=auth_token)
            profile_obj.save()
            send_mail_verification(email, auth_token)
            messages.success(request,'Please check mail for verification')
            return redirect('ecom')
    else:
        return HttpResponse('404- Page not found')

def handlelogin(request):
    if request.method == 'POST':
        loginusername = request.POST['username1']
        loginpassword = request.POST['password1']

        user_obj = User.objects.filter(username=loginusername).first()
        if user_obj is None:
            messages.success(request, 'User not found.')
            return redirect('ecom')

        profile_obj = Profile.objects.filter(user=user_obj).first()

        if not profile_obj.is_verified:
            messages.success(request, 'Profile is not verified check your mail.')
            return redirect('ecom')

        user = authenticate(username=loginusername, password=loginpassword)
        if user is None:
            messages.success(request, 'Wrong password.')
            return redirect('ecom')
        messages.success(request,f'Successfully logged in as {loginusername}')
        login(request, user)
        return redirect('/')
    return redirect('login')

def handlelogout(request):
    logout(request)
    messages.success(request,'Successfully logout')
    return redirect('ecom')

def send_mail_verification(email , token):
    subject = 'Verify your email to finish signing up for Eshop'
    message = f'Thank You for choosing Eshop. Please confirm your email by clicking the link http://127.0.0.1:8000/verify/{token}'
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [email]
    send_mail(subject, message, email_from, recipient_list)


def verify(request, auth_token):
    try:
        profile_obj = Profile.objects.filter(auth_token=auth_token).first()

        if profile_obj:
            if profile_obj.is_verified:
                messages.success(request, 'Your account is already verified.')
                return redirect('ecom')
            profile_obj.is_verified = True
            profile_obj.save()
            messages.success(request, 'Your account has been verified.')
            return redirect('ecom')
        else:
            messages.success(request,'error')
            return redirect('ecom')
    except Exception as e:
        print(e)
        return redirect('/')

def ChangePassword(request, token):
    context = {}

    try:
        profile_obj = Profile.objects.filter(auth_token=token).first()
        context = {'user_id': profile_obj.user.id}

        if request.method == 'POST':
            new_password = request.POST.get('new_password')
            confirm_password = request.POST.get('reconfirm_password')
            user_id = request.POST.get('user_id')

            if user_id is None:
                messages.success(request, 'No user id found.')
                return redirect(f'/change-password/{token}/')

            if new_password != confirm_password:
                messages.success(request, 'both should  be equal.')
                return redirect(f'/change-password/{token}/')

            if len(new_password) < 8:
                messages.error(request, 'Password is too short')
                return redirect(f'/change-password/{token}/')

            user_obj = User.objects.get(id=user_id)
            user_obj.set_password(new_password)
            user_obj.save()
            messages.success(request,'Your password has been successfully reset now you can login')
            return redirect('ecom')
    except Exception as e:
        print(e)
    return render(request, 'change-password.html', context)


def ForgetPassword(request):
    try:
        if request.method == 'POST':
            username = request.POST.get('username')

            if not User.objects.filter(username=username).first():
                messages.success(request, 'No user found with this username.')
                return redirect('ecom')

            user_obj = User.objects.get(username=username)
            token = str(uuid.uuid4())
            profile_obj = Profile.objects.get(user=user_obj)
            profile_obj.auth_token = token
            profile_obj.save()
            send_forget_password_mail(user_obj.email, token)
            messages.success(request, 'An email is sent.')
            return redirect('ecom')

    except Exception as e:
        print(e)
    return render(request, 'ecom')



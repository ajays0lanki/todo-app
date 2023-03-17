from django.shortcuts import render,redirect
from django.contrib import messages
from validate_email import validate_email
from .models import User
from django.contrib.auth import authenticate , login ,logout
from django.urls import reverse
from helpers.decorator import auth_user_should_not_access
from django.contrib.sites.shortcuts import get_current_site
from django.template.loader import render_to_string    
from django.utils.http import urlsafe_base64_decode, urlsafe_base64_encode 
from django.utils.encoding import force_bytes, force_str, smart_str
from .utils import generatortoken
from django.core.mail import EmailMessage
from django.conf import settings




def send_action_email(request, user):

     current_site=get_current_site(request)
     email_subject="Activate your account"
     email_body=render_to_string('authentication/activate.html' , {
          'user':User,
          'domain':current_site.domain,
          'uid':  urlsafe_base64_encode(force_bytes(user.pk)),
          'token': generatortoken.make_token(user),

     })
     print(email_body)
     email=EmailMessage(subject=email_subject,body=email_body,from_email= settings.EMAIL_HOST_USER,
                  to=[user.email]
                  
                  
                  )
     email.send()


@auth_user_should_not_access
def register(request): 
    
    if request.method=="POST":
          context={'has_error':False,'data': request.POST}
          email= request.POST.get('email')
          username= request.POST.get('username')
          password= request.POST.get('password')
          password2= request.POST.get('password2')


          if len(password)<6:
               messages.add_message(request,messages.ERROR,'Password should be atleast more than 5 charchter')
               context['has_error'] = True
          if password != password2:
               messages.add_message(request,messages.ERROR,'Password did not match')
               context['has_error'] = True
          if not validate_email(email):
               messages.add_message(request,messages.ERROR,'Email not matched')
               context['has_error'] = True
          if not username:     
               messages.add_message(request,messages.ERROR,'Username is required')
               context['has_error'] = True
          if User.objects.filter(username=username).exists():
               messages.add_message(request,messages.ERROR,'This username has been taken please choose another one')
               context['has_error'] = True
          if User.objects.filter(email=email).exists():
               messages.add_message(request,messages.ERROR,'This  Email has been taken please choose another one')
               context['has_error'] = True
          if context['has_error']:
               return render (request,'authentication/register.html',context)
          
          user=User.objects.create_user(username=username,email=email)
          user.set_password(password)
          user.save()
          send_action_email(request, user)
          messages.add_message(request,messages.SUCCESS,'Account created you may log-in now')
          return redirect('login')
               





    return render(request, 'authentication/register.html')



@auth_user_should_not_access

def login_user(request):     
     if request.method=="POST":
          context={'data': request.POST}
          username=request.POST.get('username')
          password=request.POST.get('password')

          user = authenticate(request, username=username,password=password)

          if not user.is_email_verified :
               messages.add_message(request,messages.ERROR,'Email is not verified , please check yoour E-mail box')
               return render(request, 'authentication/login.html', context )

          if not user :
               messages.add_message(request,messages.ERROR,'Invalid credientials')
               return render(request, 'authentication/login.html', context )
          login(request,user)
          messages.add_message(request,messages.SUCCESS,f'welcome {user.username}')
          return redirect(reverse('Homepage'))

     return render(request, 'authentication/login.html')


def logout_user(request):

     logout(request)
     messages.add_message(request,messages.SUCCESS,' Logged out successfully')
     return redirect(reverse('login'))


def activate_user(request , uidb64,  token ):
     try:

          # uid=force_str(urlsafe_base64_decode(uidb64)).decode()             
          # user = User.object.get(pk=uid)
          uuid = smart_str(urlsafe_base64_decode(uidb64))
          user = User.objects.get(id=uuid)
          print(user)
     except Exception as e :
          user=None
     if user and generatortoken.check_token(user,token):
          user.is_email_verified=True
          user.save()
          print("@@@@@@@@@@@@@@@@@@@@@@@@@@@")
          messages.add_message(request,messages.SUCCESS,'Email verified , you can now login')
          return redirect(reverse('login'))
     return render(request,'authentication/activate-failed.html',{'user': user})
     
     


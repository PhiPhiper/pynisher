#! /bin/python

import signal
import multiprocessing, logging
import os
import sys
import time
import tempfile
import gc 

import psutil

if sys.platform != 'win32':
	import resource
else:
	import ctypes
	import threading
	import warnings
	import winerror
	import win32api
	import win32job

class CpuTimeoutException (Exception): pass
class TimeoutException (Exception): pass
class MemorylimitException (Exception): pass
class SubprocessException (Exception): pass
class AnythingException (Exception): pass

# create the function the subprocess can execute
def subprocess_func(func, pipe, logger, mem_in_mb, cpu_time_limit_in_s, wall_time_limit_in_s, num_procs, grace_period_in_s, tmp_dir, args, kwargs):
	logger.debug('subprocess_func started')
	logger.debug("Function called with arguments: {}, {}".format(args, kwargs))
	if sys.platform != 'win32':
		logger.debug('Linux Detected')
		# simple signal handler to catch the signals for time limits
		def handler(signum, frame):
			# logs message with level debug on this logger 
			logger.debug("signal handler: %i"%signum)
			if (signum == signal.SIGXCPU):
				# when process reaches soft limit --> a SIGXCPU signal is sent (it normally terminats the process)
				raise(CpuTimeoutException)
			elif (signum == signal.SIGALRM):
				# SIGALRM is sent to process when the specified time limit to an alarm function elapses (when real or clock time elapses)
				logger.debug("timeout")
				raise(TimeoutException)
			raise AnythingException

		# temporary directory to store stdout and stderr
		if not tmp_dir is None:
			logger.debug('Redirecting output of the function to files. Access them via the stdout and stderr attributes of the wrapped function.')
			
			stdout = open(os.path.join(tmp_dir, 'std.out'), 'a', buffering=1)
			sys.stdout=stdout

			stderr = open(os.path.join(tmp_dir, 'std.err'), 'a', buffering=1)
			sys.stderr=stderr


		# catching all signals at this point turned out to interfer with the subprocess (e.g. using ROS)
		signal.signal(signal.SIGALRM, handler)
		signal.signal(signal.SIGXCPU, handler)
		signal.signal(signal.SIGQUIT, handler)

		# code to catch EVERY catchable signal (even X11 related ones ... )
		# only use for debugging/testing as this seems to be too intrusive.
		"""
		for i in [x for x in dir(signal) if x.startswith("SIG")]:
			try:
				signum = getattr(signal,i)
				print("register {}, {}".format(signum, i))
				signal.signal(signum, handler)
			except:
				print("Skipping %s"%i)
		"""

		# set the memory limit
		if mem_in_mb is not None:
			# byte --> megabyte
			mem_in_b = mem_in_mb*1024*1024
			# the maximum area (in bytes) of address space which may be taken by the process.
			resource.setrlimit(resource.RLIMIT_AS, (mem_in_b, mem_in_b))

		# for now: don't allow the function to spawn subprocesses itself.
		#resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
		# Turns out, this is quite restrictive, so we don't use this option by default
		if num_procs is not None:
			resource.setrlimit(resource.RLIMIT_NPROC, (num_procs, num_procs))


		# schedule an alarm in specified number of seconds
		if wall_time_limit_in_s is not None:
			signal.alarm(wall_time_limit_in_s)
		
		if cpu_time_limit_in_s is not None:
			# From the Linux man page:
			# When the process reaches the soft limit, it is sent a SIGXCPU signal.
			# The default action for this signal is to terminate the process.
			# However, the signal can be caught, and the handler can return control 
			# to the main program. If the process continues to consume CPU time,
			# it will be sent SIGXCPU once per second until the hard limit is reached,
			# at which time it is sent SIGKILL.
			resource.setrlimit(resource.RLIMIT_CPU, (cpu_time_limit_in_s,cpu_time_limit_in_s+grace_period_in_s))

		# the actual function call
		try:
			logger.debug("call function")
			return_value = ((func(*args, **kwargs), 0))
			logger.debug("function returned properly: {}".format(return_value))
		except MemoryError:
			return_value = (None, MemorylimitException)

		except OSError as e:
			if (e.errno == 11):
				return_value = (None, SubprocessException)
			else:
				return_value = (None, AnythingException)

		except CpuTimeoutException:
			return_value = (None, CpuTimeoutException)

		except TimeoutException:
			return_value = (None, TimeoutException)

		except AnythingException as e:
			return_value = (None, AnythingException)
		except:
			raise
			logger.debug("Some wired exception occured!")
			
		finally:
			try:
				logger.debug("return value: {}".format(return_value))
				
				pipe.send(return_value)
				pipe.close()

			except:
				# this part should only fail if the parent process is alread dead, so there is not much to do anymore :)
				pass
			finally:
				# recursively kill all children
				p = psutil.Process()
				for child in p.children(recursive=True):
					child.kill()
	else:
		logger.debug('Win32 Detected')
		# simple signal handler to catch the signals for time limits
		def handler(signum, frame):
			# logs message with level debug on this logger 
			logger.debug("signal handler: %i"%signum)
			if (signum == signal.SIGILL):
				# when process reaches soft limit --> a SIGXCPU signal is sent (it normally terminats the process)
				raise(CpuTimeoutException)
			raise AnythingException
			
		# temporary directory to store stdout and stderr
		stdout = None
		stderr = None
		stdoutold = sys.stdout
		stderrold = sys.stderr
		if tmp_dir is not None:
			logger.debug('Redirecting output of the function to files. Access them via the stdout and stderr attributes of the wrapped function.')
			stdout = open(os.path.join(tmp_dir, 'std.out'), 'a', buffering=1)
			sys.stdout=stdout

			stderr = open(os.path.join(tmp_dir, 'std.err'), 'a', buffering=1)
			sys.stderr=stderr


		# catching all signals at this point turned out to interfer with the subprocess (e.g. using ROS)
		# signal.signal(signal.SIGALRM, handler)
		#signal.signal(signal.SIGILL, handler)
		#signal.signal(signal.SIGQUIT, handler)
		# code to catch EVERY catchable signal (even X11 related ones ... )
		# only use for debugging/testing as this seems to be too intrusive.
		"""
		for i in [x for x in dir(signal) if x.startswith("SIG")]:
			try:
				signum = getattr(signal,i)
				print("register {}, {}".format(signum, i))
				signal.signal(signum, handler)
			except:
				print("Skipping %s"%i)
		"""
		hjob = win32job.CreateJobObject(None, '')
		hprocess = win32api.GetCurrentProcess()
		try:
			win32job.AssignProcessToJobObject(hjob, hprocess)
		except win32job.error as e:
			if (e.winerror != winerror.ERROR_ACCESS_DENIED or
				sys.getwindowsversion() >= (6, 2) or
				not win32job.IsProcessInJob(hprocess, None)):
				raise
			warnings.warn('The process is already in a job. Nested jobs are not '
				'supported prior to Windows 8.')
			hprocess = win32api.GetCurrentProcess()
			try:
				win32job.AssignProcessToJobObject(hjob, hprocess)
			except win32job.error as e:
				if (e.winerror != winerror.ERROR_ACCESS_DENIED or
					sys.getwindowsversion() >= (6, 2) or
					not win32job.IsProcessInJob(hprocess, None)):
					raise
				warnings.warn('The process is already in a job. Nested jobs are not '
					'supported prior to Windows 8.')
		info = win32job.QueryInformationJobObject(hjob,
			win32job.JobObjectExtendedLimitInformation)
		logger.debug('Win32Job created')

		# set the memory limit
		if mem_in_mb is not None:
			# the maximum area (in bytes) of address space which may be taken by the process.
			#resource.setrlimit(resource.RLIMIT_AS, (mem_in_b, mem_in_b))
			info['JobMemoryLimit'] = mem_in_mb*1024*1024
			info['BasicLimitInformation']['LimitFlags'] |= (
				win32job.JOB_OBJECT_LIMIT_JOB_MEMORY)
		logger.debug('Win32Job JobMemoryLimit set')

		# for now: don't allow the function to spawn subprocesses itself.
		#resource.setrlimit(resource.RLIMIT_NPROC, (1, 1))
		# Turns out, this is quite restrictive, so we don't use this option by default
		if num_procs is not None:
			#resource.setrlimit(resource.RLIMIT_NPROC, (num_procs, num_procs))
			info['BasicLimitInformation']['ActiveProcessLimit'] = num_procs
			info['BasicLimitInformation']['LimitFlags'] |= (
				win32job.JOB_OBJECT_LIMIT_ACTIVE_PROCESS)
		logger.debug('Win32Job ActiveProcessLimit set')

		win32job.SetInformationJobObject(hjob,
			win32job.JobObjectExtendedLimitInformation, info)
		# the actual function call
		try:
			logger.debug("call function")
			class ThreadWithExceptionAndReturn(threading.Thread):
				def __init__(self, logger, *args, **kwargs):
					threading.Thread.__init__(self, *args, **kwargs)
					self.logger = logger
					self.rv = None
					self.ex = None

				def run(self):
					try:
						self.rv = self._target(*self._args, **self._kwargs)
					except BaseException as e:
						self.ex = e

				def get_id(self):			
					# returns id of the respective thread 
					if hasattr(self, '_thread_id'): 
						return self._thread_id 
					for id, thread in threading._active.items(): 
						if thread is self: 
							return id
			
				def raise_exception(self, ex): 
					thread_id = self.get_id() 
					res = ctypes.pythonapi.PyThreadState_SetAsyncExc(ctypes.c_long(thread_id), 
																	 ctypes.py_object(ex)) 
					if res > 1: 
						ctypes.pythonapi.PyThreadState_SetAsyncExc(tctypes.c_long(hread_id), 0)

			# Set as daemon so it gets killed with the process
			t = ThreadWithExceptionAndReturn(target = func, logger = logger, args = args, kwargs = kwargs, daemon = True)
			start = time.time()
			t.start()
			if wall_time_limit_in_s is not None or cpu_time_limit_in_s is not None:
				while(t.isAlive()):
					if wall_time_limit_in_s is not None and wall_time_limit_in_s < time.time()-start:
						t.raise_exception(TimeoutException)
						t.join(0.001)
						raise TimeoutException
					if cpu_time_limit_in_s is not None:
						pt = next((pt for pt in psutil.Process().threads() if pt.id == t.get_id()), None)
						if cpu_time_limit_in_s < pt.user_time + pt.system_time:
							t.raise_exception(CpuTimeoutException)
							t.join(grace_period_in_s if grace_period_in_s is not None else 0.001)
							logger.debug('CPU Time Limit reached. Total CPU time: {}'.format(pt.user_time + pt.system_time))
							raise CpuTimeoutException
					t.join(0.01)
			else:
				t.join()
			if t.ex is not None:
					raise t.ex
			return_value = (t.rv, 0)
			logger.debug("function returned properly: {}".format(return_value))
		except MemoryError:
			logger.debug('MemoryError')
			return_value = (None, MemorylimitException)			

		except OSError as e:
			logger.debug('OSError')
			if (e.errno == 12):
				return_value = (None, SubprocessException)
			else:
				return_value = (None, AnythingException)

		except CpuTimeoutException:
			logger.debug('CpuTimeoutException')
			return_value = (None, CpuTimeoutException)

		except TimeoutException:
			logger.debug('TimeoutException')
			return_value = (None, TimeoutException)

		except AnythingException as e:
			logger.debug('AnythingException')
			return_value = (None, AnythingException)
		except BaseException as e:
			logger.debug('OtherError')
			raise e
			logger.debug("Some wired exception occured!")
			
		finally:
			try:
				# lift restrictions to allow space for return values and variables
				# info['BasicLimitInformation']['LimitFlags'] = 0
				# win32job.SetInformationJobObject(hjob,
				# 	win32job.JobObjectExtendedLimitInformation, info)
				logger.debug("return value: {}".format(return_value))
				
				pipe.send(return_value)
				pipe.close()

			except:
				# this part should only fail if the parent process is alread dead, so there is not much to do anymore :)
				pass
			finally:
				# sys.stdout = stdoutold
				# sys.stderr = stderrold
				# if stdout is not None: stdout.close()
				# if stderr is not None: stderr.close()

				# recursively kill all children
				logger.debug("Child Pid: {}".format(os.getpid()))
				p = psutil.Process()
				for child in p.children(recursive=True):
					child.kill()
				# rt = 0
				# win32job.TerminateJobObject(hjob, rt)
			



class enforce_limits (object):
	def __init__(self, mem_in_mb=None, cpu_time_in_s=None, wall_time_in_s=None, num_processes=None, grace_period_in_s = None, logger = None, capture_output=False):
		self.mem_in_mb = mem_in_mb
		self.cpu_time_in_s = cpu_time_in_s
		self.num_processes = num_processes
		self.wall_time_in_s = wall_time_in_s
		self.grace_period_in_s = 0 if grace_period_in_s is None else grace_period_in_s
		self.logger = logger if logger is not None else multiprocessing.get_logger()
		self.capture_output = capture_output
		
		if self.mem_in_mb is not None:
			self.logger.debug("Restricting your function to {} mb memory.".format(self.mem_in_mb))
		if self.cpu_time_in_s is not None:
			self.logger.debug("Restricting your function to {} seconds cpu time.".format(self.cpu_time_in_s))
		if self.wall_time_in_s is not None:
			self.logger.debug("Restricting your function to {} seconds wall time.".format(self.wall_time_in_s))
		if self.num_processes is not None:
			self.logger.debug("Restricting your function to {} threads/processes.".format(self.num_processes))
		if self.grace_period_in_s is not None:
			self.logger.debug("Allowing a grace period of {} seconds.".format(self.grace_period_in_s))

		
	def __call__ (self, func):
		
		class function_wrapper(object):
			def __init__(self2, func):
				self2.func = func
				self2._reset_attributes()
			
			def _reset_attributes(self2):
				self2.result = None
				self2.exit_status = None
				self2.resources_function = None
				self2.resources_pynisher = None
				self2.wall_clock_time = None	
				self2.stdout = None
				self2.stderr = None	
			
			def __call__(self2, *args, **kwargs):
			
				self2._reset_attributes()
				self.logger.debug("Parent Pid: {}".format(os.getpid()))

				# create a pipe to retrieve the return value
				parent_conn, child_conn = multiprocessing.Pipe(False)
				#import pdb; pdb.set_trace()
				tmp_dir = None
				tmp_dir_name = None
				if self.capture_output:
					tmp_dir = tempfile.TemporaryDirectory()
					tmp_dir_name = tmp_dir.name
					if not os.path.exists(tmp_dir_name):
						os.makedirs(tmp_dir_name)
				# create and start the process
				subproc = multiprocessing.Process(target=subprocess_func,
												  args = (self2.func, child_conn, self.logger, self.mem_in_mb,
														  self.cpu_time_in_s, self.wall_time_in_s, self.num_processes,
														  self.grace_period_in_s, tmp_dir_name, args , kwargs))
				self.logger.debug("Function called with argument: {}, {}".format(args, kwargs))

				# start the process
				
				#subprocess_func(self2.func, child_conn, self.logger, self.mem_in_mb, self.cpu_time_in_s, self.wall_time_in_s, self.num_processes, self.grace_period_in_s, tmp_dir_name, args , kwargs)
				start = time.time()
				subproc.start()
				child_conn.close()
				

				try:
					# read the return value
					if (self.wall_time_in_s is not None):
						if parent_conn.poll(self.wall_time_in_s+self.grace_period_in_s):
							self2.result, self2.exit_status = parent_conn.recv()
						else:
							subproc.terminate()
							self2.exit_status = TimeoutException
							
					else:
						self2.result, self2.exit_status = parent_conn.recv()

				except EOFError:    # Don't see that in the unit tests :(
					self.logger.debug("Your function call closed the pipe prematurely -> Subprocess probably got an uncatchable signal.")
					self2.exit_status = AnythingException

				except:
					self.logger.debug("Something else went wrong, sorry.")
				finally:
					if sys.platform != 'win32':
						self2.resources_function = resource.getrusage(resource.RUSAGE_CHILDREN)
						self2.resources_pynisher = resource.getrusage(resource.RUSAGE_SELF)
					else:
						subproc.pid
					# 	self2.resources_function = resource.getrusage(resource.RUSAGE_CHILDREN)
					# 	self2.resources_pynisher = resource.getrusage(resource.RUSAGE_SELF)
					self2.wall_clock_time = time.time()-start
					self2.exit_status = 5 if self2.exit_status is None else self2.exit_status

					# don't leave zombies behind
					subproc.join()

					# recover stdout and stderr if requested
					if self.capture_output:
						with open(os.path.join(tmp_dir.name, 'std.out'),'r') as fh:
							self2.stdout = fh.read()
						with open(os.path.join(tmp_dir.name, 'std.err'),'r') as fh:
							self2.stderr = fh.read()
						if tmp_dir is not None: tmp_dir.cleanup()
				return (self2.result)
		return (function_wrapper(func))
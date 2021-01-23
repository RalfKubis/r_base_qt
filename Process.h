#pragma once

#ifdef _WIN32
#include <windows.h>
#endif

#include "r_base/filesystem.h"

#include <vector>
#include <map>
#include <string>
#include <memory>

#include <QObject>
#include <QProcess>


namespace nsBase
{

/**
*/
class Process
// :    public QObject
{
//  Q_OBJECT

    public : using
        process_ref_t = ::std::unique_ptr<Process>;


    public : using
        List = ::std::vector<process_ref_t>;

    public : using
        MultiMap = ::std::multimap<::std::string, process_ref_t>;

    public : using
        ProcessID = unsigned int;

    public : using
        paths_t = ::std::vector<::fs::path>;

    public : using
        arguments_t = ::std::vector<::std::string>;


    public :
        Process();

    public :
        ~Process();

    public : void
        start(
                bool    inElevate            = false
            ,   bool    inInheritEnvironment = true
            ,   bool    inInheritDescriptors = false
            );

    /** Resume client processes main thread.
    */
    public : void
        resume();

    public : int
        wait();

    public : void
        detach();

    /**
        Try to terminate the current process.
        This function is not supposed to return.

        \param  exit_code  The exit code to be used.
    */
    public : static void
        exit(
                int exit_code
            );

    /**
        Test if the process is running.
    */
    public : bool
        isRunning();

    /** Once called, an internal timer will call this slot continuously (100ms)
        until the process is terminated.
        Then the signal 'terminated' is emitted.
    */
    public slots : void
        checkRunning();

    /** If started with start(), or checkRunning() was invoked, this signal is
        emitted when the process had terminated.
    */
//    signals : void
//        terminated();

#ifdef _WIN32
    private : PROCESS_INFORMATION
        mProcessInfo;

    private : STARTUPINFO
        mStartupInfo;
#endif


////////////////////////////////////////////////////////////////////////////////
/** \name Process ID
@{*/
    private : ProcessID
        mProcessId {};

    public : ProcessID
        processId() const;
//@}


////////////////////////////////////////////////////////////////////////////////
/** \name Permissions/Elevation
@{*/
    public : static bool
        userIsAdmin();

    public : static bool
        elevated();
//@}

    /**
        Attempt to terminate the process.
    */
    public : void
        terminate(
                int exit_code
            );

    /**
        On unix systems where fork/exec is used to spawn processes the open
        descriptors get inherited to the child process.
        For all open descriptors (except 0,1,2), the FD_CLOEXEC flag is set.
        By this, these descriptors are automatically closed when exec()
        is called.
    */
    public : static void
        flagAllDescriptorsToCloseOnExec();

    /**
        Get a list of all running processes.

        \param [in,out] outListOfProcess    Gets cleared and filled with
        instances that represent running processes. The instances get the
        property 'ProcessID' set accordingly. All other properties
        remain empty.
    */
    public : static List
        processes();

    /**
        For each target modules, search all processes that currently use the
        module. Internally the function uses preprocessed file paths.
        Preprocessed paths are absolute, canonical, lower letter and native.

        \param  inModuleFilePaths       The file paths of the target modules.
            Internally absolute, canonical, native versions of these paths
            are generated and used. I.e., the function should be able to cope
            with relative, non-native, non-canonical paths.
        \param [in,out] outUsedModules  Gets cleared and filled with
            preprocessed module paths (as keys) that are in use by at least
            one process. The values are references to the processes that use
            the addressed module. New instances of class Process are created.
            One for each affected Process.

        \return
        Success value.
    */
    public : static void
        processesByModule(
                paths_t const & inModuleFilePaths
            ,   MultiMap      & outUsedModules
            );

    /**
        Get an instance that represents the calling process.
    */
    public : static process_ref_t
        self();

    /**
        Get all modules that are loaded by the process.

        \param [in,out] outModuleFilePaths  Gets cleared and filled with
            absolute file paths of the detected modules in drive letter form.

        \return
        Success value.
    */
    public : paths_t
        modules() const;

    /**
        Get the name of the executable file path for the specified process.
        The function returns the path in device form, rather than drive letters.
        For example, the file name C:\Windows\System32\Ctype.nls would look as
        follows in device form :
            \Device\Harddisk0\Partition1\Windows\System32\Ctype.nls

        \param [in,out] outValue    The file path or empty if the path is not
            accessible.

        \return
        Success value.
    */
    public : ::fs::path
        imageFilePath() const;


////////////////////////////////////////////////////////////////////////////////
/** \name When starting a new Process
@{*/
    public : ::fs::path
        mWorkingDirectory;

    public : ::fs::path
        mExePath;

    public : arguments_t
        mListOfArgument;

    public : arguments_t
        mListOfEnvironmentVal;

    public : int
        mExitCode {};

    private : QProcess *
        mProcess {};
//@}
};

}

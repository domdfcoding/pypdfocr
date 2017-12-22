#!/usr/bin/env python2.7
# Copyright 2013 Virantha Ekanayake All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import argparse
import sys, os, traceback, time
import logging
import shutil, glob
import itertools
from functools import wraps

from version import __version__
from PIL import Image
import yaml

import multiprocessing
# Replace the Popen routine to allow win32 pyinstaller to build
from multiprocessing import forking
from pypdfocr_multiprocessing import _Popen
forking.Popen = _Popen

from pypdfocr_pdf import PyPdf
from pypdfocr_tesseract import PyTesseract
from pypdfocr_gs import PyGs
from pypdfocr_watcher import PyPdfWatcher
from pypdfocr_preprocess import PyPreprocess

def error(text):
    print("ERROR: %s" % text)
    sys.exit(-1)

# decorator to retry multiple times
def retry(count=5, exc_type = Exception):
    def decorator(func):
        @wraps(func)
        def result(*args, **kwargs):
            for _ in range(count):
                try:
                    return func(*args, **kwargs)
                except exc_type:
                    pass
                raise
        return result
    return decorator

@retry(count=6, exc_type=IOError)
def open_file_with_timeout(parser, arg):
    f = open(arg, 'r')
    return f

"""
    Make scanned PDFs searchable using Tesseract-OCR
.. automodule:: pypdfocr
    :private-members:
"""

class PyPDFOCR(object):
    """
        The main clas.  Performs the following functions:

        * Parses command line options
        * Optionally just watches a directory for new PDF's to OCR; once a file appears, it does the next step
        * Runs a single file conversion:
            * Runs ghostscript to get tiff/jpg
            * Runs Tesseract-OCR to do the actual OCR
            * Takes the HOCR from Tesseract and creates a new PDF with the text overlay
        * 
    """

    def __init__ (self):
        """ Initializes the GhostScript, Tesseract, and PDF helper classes.
        """
        self.config = {}

    def get_options(self, argv):
        """
            Parse the command-line options and set the following object properties:

            :param argv: usually just sys.argv[1:]
            :returns: Nothing

            :ivar debug: Enable logging debug statements
            :ivar verbose: Enable verbose logging
            :ivar enable_filing: Whether to enable post-OCR filing of PDFs
            :ivar pdf_filename: Filename for single conversion mode
            :ivar watch_dir: Directory to watch for files to convert
            :ivar config: Dict of the config file
            :ivar watch: Whether folder watching mode is turned on
            :ivar enable_evernote: Enable filing to evernote

        """
        p = argparse.ArgumentParser(
                description = "Convert scanned PDFs into their OCR equivalent.  Depends on GhostScript and Tesseract-OCR being installed.",
                epilog = "PyPDFOCR version %s (Copyright 2013 Virantha Ekanayake)" % __version__,
                )

        p.add_argument('-d', '--debug', action='store_true',
            default=False, dest='debug', help='Turn on debugging')

        p.add_argument('-v', '--verbose', action='store_true',
            default=False, dest='verbose', help='Turn on verbose mode')

        #---------
        # Single or watch mode
        #--------
        single_or_watch_group = p.add_mutually_exclusive_group(required=True)
        # Positional argument for single file conversion
        single_or_watch_group.add_argument("pdf_filename", nargs="?", help="Scanned pdf file to OCR")
        # Watch directory for watch mode
        single_or_watch_group.add_argument('-w', '--watch', 
             dest='watch_dir', help='Watch given directory and run ocr automatically until terminated')

         # Add flow option to single mode extract_images,preprocess,ocr,write

        args = p.parse_args(argv)

        self.debug = args.debug
        self.verbose = args.verbose
        self.pdf_filename = args.pdf_filename
        self.lang = args.lang
        self.watch_dir = args.watch_dir

        if self.debug:
            logging.basicConfig(level=logging.DEBUG, format='%(message)s')

        if self.verbose:
            logging.basicConfig(level=logging.INFO, format='%(message)s')


        self.watch = False

    def _clean_up_files(self, files):
        """
            Helper function to delete files
            :param files: List of files to delete
            :type files: list
            :returns: None
        """
        for f in files:
            try:
                os.remove(f)
            except:
                logging.debug("Error removing file %s .... continuing" % f)
  
    def _setup_external_tools(self):
        """
            Instantiate the external tool wrappers with their config dicts
        """

        self.gs = PyGs(self.config.get('ghostscript',{}))
        self.ts = PyTesseract(self.config.get('tesseract',{}))
        self.pdf = PyPdf(self.gs)
        self.preprocess = PyPreprocess(self.config.get('preprocess', {}))

        return

    def run_conversion(self, pdf_filename):
        """
            Does the following:
            
            - Convert the PDF using GhostScript to TIFF and JPG
            - Run Tesseract on the TIFF to extract the text into HOCR (html)
            - Use PDF generator to overlay the text on the JPG and output a new PDF
            - Clean up temporary image files
            
            :param pdf_filename: Scanned PDF
            :type pdf_filename: string
            :returns: OCR'ed PDF
            :rtype: filename string
        """
        print ("Starting conversion of %s" % pdf_filename)
        try:
            # Make the images for Tesseract
            img_dpi, glob_img_filename = self.gs.make_img_from_pdf(pdf_filename)

            fns = glob.glob(glob_img_filename)
        
        except Exception:
            raise

        try:
            # Preprocess
            if not self.skip_preprocess:
                preprocess_imagefilenames = self.preprocess.preprocess(fns)
            else:
                logging.info("Skipping preprocess step")
                preprocess_imagefilenames = fns
            # Run teserract
            self.ts.lang = self.lang
            hocr_filenames = self.ts.make_hocr_from_pnms(preprocess_imagefilenames)
            
            # Generate new pdf with overlayed text
            #ocr_pdf_filename = self.pdf.overlay_hocr(tiff_dpi, hocr_filename, pdf_filename)
            ocr_pdf_filename = self.pdf.overlay_hocr_pages(img_dpi, hocr_filenames, pdf_filename)

        finally:
            # Clean up the files
            time.sleep(1)
            if not self.debug:
                # Need to clean up the original image files before preprocessing
                if locals().has_key("fns"): # Have to check if this was set before exception raised
                    logging.info("Cleaning up %s" % fns)
                    self._clean_up_files(fns)

                if locals().has_key("preprocess_imagefilenames"):  # Have to check if this was set before exception raised
                    logging.info("Cleaning up %s" % preprocess_imagefilenames)
                    self._clean_up_files(preprocess_imagefilenames) # splat the hocr_filenames as it is a list of pairs
                    for ext in [".hocr", ".html", ".txt"]:
                        fns_to_remove = [os.path.splitext(fn)[0]+ext for fn in preprocess_imagefilenames]
                        logging.info("Cleaning up %s" % fns_to_remove)
                        self._clean_up_files(fns_to_remove) # splat the hocr_filenames as it is a list of pairs
                    # clean up the hocr input (jpg) and output (html) files
                    #self._clean_up_files(itertools.chain(*hocr_filenames)) # splat the hocr_filenames as it is a list of pairs
                    # Seems like newer tessearct > 3.03 is now creating .txt files with the OCR text?/?
                    #self._clean_up_files([x[1].replace(".hocr", ".txt") for x in hocr_filenames])


        print ("Completed conversion successfully to %s" % ocr_pdf_filename)
        return ocr_pdf_filename

    def go(self, argv):
        """ 
            The main entry point into PyPDFOCR

            #. Parses options
            #. If filing is enabled, call :func:`_setup_filing`
            #. If watch is enabled, start the watcher
            #. :func:`run_conversion`
        """
        # Read the command line options
        self.get_options(argv)

        # Setup tesseract and ghostscript
        self._setup_external_tools()

        # Setup the pdf filing if enabled
        if self.enable_filing:
            self._setup_filing()

        # Do the actual conversion followed by optional filing and email
        if self.watch:
            while True:  # Make sure the watcher doesn't terminate
                try:
                    py_watcher = PyPdfWatcher(self.watch_dir, self.config.get('watch'))
                    for pdf_filename in py_watcher.start():
                        self._convert_and_file_email(pdf_filename)
                except KeyboardInterrupt:
                    break
                except Exception as e:
                    print traceback.print_exc(e)
                    py_watcher.stop()
                    
        else:
            self._convert_and_file_email(self.pdf_filename)

    def _convert_and_file_email(self, pdf_filename):
        """
            Helper function to run the conversion, then do the optional filing, and optional emailing.
        """
        ocr_pdffilename = self.run_conversion(pdf_filename)
        filing = "None"

def main(): # pragma: no cover 
    multiprocessing.freeze_support()
    script = PyPDFOCR()
    script.go(sys.argv[1:])

if __name__ == '__main__':
    main()


